package com.fivucsas.identity.application.service;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.AuthSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthSessionQueryService}: routing between repo
 * methods based on filter combinations + DTO shape verification.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuthSessionQueryService — admin list")
class AuthSessionQueryServiceTest {

    @Mock
    private AuthSessionRepository authSessionRepository;

    @InjectMocks
    private AuthSessionQueryService service;

    private UUID tenantId;
    private UUID userId;
    private AuthSession session;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        userId = UUID.randomUUID();

        Tenant tenant = Tenant.builder().id(tenantId).name("Marmara").build();
        User user = User.builder().id(userId)
                .email("user@marun.edu.tr").firstName("A").lastName("B")
                .tenant(tenant).build();
        AuthFlow flow = AuthFlow.builder().id(UUID.randomUUID()).name("login").build();

        session = AuthSession.builder()
                .id(UUID.randomUUID())
                .tenant(tenant)
                .user(user)
                .authFlow(flow)
                .operationType(OperationType.APP_LOGIN)
                .status(AuthSessionStatus.IN_PROGRESS)
                .currentStepOrder(2)
                .startedAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(600))
                .ipAddress("203.0.113.7")
                .userAgent("Mozilla/5.0")
                .build();
    }

    @Test
    @DisplayName("rejects null tenantId — admin endpoint MUST be tenant-scoped")
    void rejectsNullTenant() {
        assertThatThrownBy(() ->
                service.listForTenant(null, List.of(), null, 0, 20))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tenantId");
    }

    @Test
    @DisplayName("no filters → findAllByTenantId, sorted startedAt DESC")
    void noFiltersHitsTenantOnly() {
        Page<AuthSession> page = new PageImpl<>(List.of(session));
        when(authSessionRepository.findAllByTenantId(eq(tenantId), any(Pageable.class))).thenReturn(page);

        Map<String, Object> body = service.listForTenant(tenantId, null, null, 0, 20);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(authSessionRepository).findAllByTenantId(eq(tenantId), captor.capture());
        Pageable used = captor.getValue();
        assertThat(used.getPageNumber()).isEqualTo(0);
        assertThat(used.getPageSize()).isEqualTo(20);
        assertThat(used.getSort()).isEqualTo(Sort.by(Sort.Direction.DESC, "startedAt"));
        assertThat(((List<?>) body.get("content"))).hasSize(1);
        assertThat(body.get("totalElements")).isEqualTo(1L);
        verify(authSessionRepository, never()).findAllByTenantIdAndStatusIn(any(), any(), any());
        verify(authSessionRepository, never()).findAllByTenantIdAndUserId(any(), any(), any());
        verify(authSessionRepository, never()).findAllByTenantIdAndUserIdAndStatusIn(any(), any(), any(), any());
    }

    @Test
    @DisplayName("status filter only → findAllByTenantIdAndStatusIn")
    void statusFilterRoute() {
        List<AuthSessionStatus> filter = List.of(AuthSessionStatus.IN_PROGRESS, AuthSessionStatus.CREATED);
        when(authSessionRepository.findAllByTenantIdAndStatusIn(eq(tenantId), eq(filter), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(session)));

        service.listForTenant(tenantId, filter, null, 0, 20);

        verify(authSessionRepository).findAllByTenantIdAndStatusIn(eq(tenantId), eq(filter), any(Pageable.class));
        verify(authSessionRepository, never()).findAllByTenantId(any(), any());
    }

    @Test
    @DisplayName("user filter only → findAllByTenantIdAndUserId")
    void userFilterRoute() {
        when(authSessionRepository.findAllByTenantIdAndUserId(eq(tenantId), eq(userId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(session)));

        service.listForTenant(tenantId, null, userId, 0, 20);

        verify(authSessionRepository).findAllByTenantIdAndUserId(eq(tenantId), eq(userId), any(Pageable.class));
    }

    @Test
    @DisplayName("user + status → findAllByTenantIdAndUserIdAndStatusIn")
    void userAndStatusRoute() {
        List<AuthSessionStatus> filter = List.of(AuthSessionStatus.COMPLETED);
        when(authSessionRepository.findAllByTenantIdAndUserIdAndStatusIn(
                eq(tenantId), eq(userId), eq(filter), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.listForTenant(tenantId, filter, userId, 0, 20);

        verify(authSessionRepository).findAllByTenantIdAndUserIdAndStatusIn(
                eq(tenantId), eq(userId), eq(filter), any(Pageable.class));
    }

    @Test
    @DisplayName("DTO maps id, userId, tenantId, status, step counts, ip, userAgent — no tokens")
    void dtoShape() {
        when(authSessionRepository.findAllByTenantId(eq(tenantId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(session)));

        Map<String, Object> body = service.listForTenant(tenantId, null, null, 0, 20);

        @SuppressWarnings("unchecked")
        List<com.fivucsas.identity.application.dto.response.AuthSessionListItemResponse> items =
                (List<com.fivucsas.identity.application.dto.response.AuthSessionListItemResponse>) body.get("content");
        assertThat(items).hasSize(1);
        var item = items.get(0);
        assertThat(item.id()).isEqualTo(session.getId());
        assertThat(item.userId()).isEqualTo(userId);
        assertThat(item.tenantId()).isEqualTo(tenantId);
        assertThat(item.status()).isEqualTo(AuthSessionStatus.IN_PROGRESS);
        assertThat(item.currentStep()).isEqualTo(2);
        assertThat(item.ipAddress()).isEqualTo("203.0.113.7");
        assertThat(item.userAgent()).isEqualTo("Mozilla/5.0");
    }

    @Test
    @DisplayName("page size capped at MAX_PAGE_SIZE (200)")
    void pageSizeCapped() {
        when(authSessionRepository.findAllByTenantId(eq(tenantId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.listForTenant(tenantId, null, null, 0, 99_999);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(authSessionRepository).findAllByTenantId(eq(tenantId), captor.capture());
        assertThat(captor.getValue().getPageSize()).isEqualTo(200);
    }

    @Test
    @DisplayName("negative page coerced to 0; size below 1 coerced to 1")
    void boundsCoerced() {
        when(authSessionRepository.findAllByTenantId(eq(tenantId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.listForTenant(tenantId, null, null, -5, 0);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(authSessionRepository).findAllByTenantId(eq(tenantId), captor.capture());
        assertThat(captor.getValue().getPageNumber()).isEqualTo(0);
        assertThat(captor.getValue().getPageSize()).isEqualTo(1);
    }

    @Test
    @DisplayName("PageRequest sort matches descending startedAt")
    void sortIsStartedAtDesc() {
        when(authSessionRepository.findAllByTenantId(eq(tenantId), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of()));

        service.listForTenant(tenantId, null, null, 0, 20);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(authSessionRepository).findAllByTenantId(eq(tenantId), captor.capture());
        Pageable expected = PageRequest.of(0, 20, Sort.by(Sort.Direction.DESC, "startedAt"));
        assertThat(captor.getValue()).isEqualTo(expected);
    }
}
