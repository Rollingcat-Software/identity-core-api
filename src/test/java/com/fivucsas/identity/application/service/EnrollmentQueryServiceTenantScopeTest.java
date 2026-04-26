package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies {@link EnrollmentQueryService#getAllEnrollments(UUID)} routes
 * through the tenant-scoped repository path for non-SUPER_ADMIN callers
 * (scope arg != null) and falls through to {@code findAll()} for SUPER_ADMIN.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EnrollmentQueryService — tenant-scoped listing")
class EnrollmentQueryServiceTenantScopeTest {

    @Mock
    private UserEnrollmentRepositoryPort userEnrollmentRepository;

    @InjectMocks
    private EnrollmentQueryService service;

    private UUID tenantId;
    private UserEnrollment enrollment;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        Tenant tenant = Tenant.builder().id(tenantId).name("Marmara").build();
        User user = User.builder().id(UUID.randomUUID())
                .email("user@marun.edu.tr")
                .firstName("A").lastName("B")
                .tenant(tenant).build();
        enrollment = UserEnrollment.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tenant(tenant)
                .status(EnrollmentStatus.ENROLLED)
                .enrolledAt(Instant.now())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
    }

    @Test
    @DisplayName("null scope (SUPER_ADMIN) → findAll()")
    void superAdminHitsFindAll() {
        when(userEnrollmentRepository.findAll()).thenReturn(List.of(enrollment));

        var result = service.getAllEnrollments(null);

        assertThat(result).hasSize(1);
        verify(userEnrollmentRepository).findAll();
        verify(userEnrollmentRepository, never()).findAllByTenantId(any());
    }

    @Test
    @DisplayName("tenant scope → findAllByTenantId()")
    void tenantScopedCallerHitsByTenant() {
        when(userEnrollmentRepository.findAllByTenantId(tenantId)).thenReturn(List.of(enrollment));

        var result = service.getAllEnrollments(tenantId);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getTenantId()).isEqualTo(tenantId.toString());
        verify(userEnrollmentRepository).findAllByTenantId(tenantId);
        verify(userEnrollmentRepository, never()).findAll();
    }

    @Test
    @DisplayName("fail-closed sentinel scope → empty-returning tenant query")
    void failClosedSentinelReturnsEmpty() {
        UUID sentinel = new UUID(0L, 0L);
        when(userEnrollmentRepository.findAllByTenantId(sentinel)).thenReturn(List.of());

        var result = service.getAllEnrollments(sentinel);

        assertThat(result).isEmpty();
        verify(userEnrollmentRepository).findAllByTenantId(sentinel);
    }

    // Convenience: mockito matcher without import clutter
    private static <T> T any() {
        return org.mockito.ArgumentMatchers.any();
    }
}
