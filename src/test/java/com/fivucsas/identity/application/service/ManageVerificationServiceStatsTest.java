package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.service.verification.VerificationStepHandlerRegistry;
import com.fivucsas.identity.domain.model.auth.FlowType;
import com.fivucsas.identity.domain.model.auth.VerificationSessionStatus;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.repository.AuthFlowRepository;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.VerificationDocumentRepository;
import com.fivucsas.identity.repository.VerificationSessionRepository;
import com.fivucsas.identity.repository.VerificationStepResultRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Covers the new GET endpoints added in {@code fix/tenant-scope-other-controllers}:
 * {@code /verification/flows}, {@code /verification/stats},
 * {@code /verification/sessions}.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ManageVerificationService — stats / flows / sessions")
class ManageVerificationServiceStatsTest {

    @Mock
    private VerificationSessionRepository sessionRepository;

    @Mock
    private VerificationStepResultRepository stepResultRepository;

    @Mock
    private VerificationDocumentRepository documentRepository;

    @Mock
    private AuthFlowRepository authFlowRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JpaTenantRepository tenantRepository;

    @Mock
    private VerificationStepHandlerRegistry handlerRegistry;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private ManageVerificationService service;

    private UUID tenantId;
    private Tenant tenant;
    private User user;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        tenant = Tenant.builder().id(tenantId).name("Marmara").build();
        user = User.builder().id(UUID.randomUUID())
                .email("user@marun.edu.tr").firstName("A").lastName("B")
                .tenant(tenant).build();
    }

    private VerificationSession sessionWithStatus(VerificationSessionStatus status) {
        AuthFlow flow = AuthFlow.builder()
                .id(UUID.randomUUID()).tenant(tenant).name("KYC")
                .flowType(FlowType.VERIFICATION).build();
        return VerificationSession.builder()
                .id(UUID.randomUUID()).user(user).tenant(tenant).flow(flow)
                .status(status).currentStepNumber(0)
                .createdAt(Instant.now()).updatedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    @Test
    @DisplayName("getVerificationStats aggregates totals, success rate, per status")
    void statsAggregation() {
        when(sessionRepository.findAllByTenantIdOrderByCreatedAtDesc(tenantId))
                .thenReturn(List.of(
                        sessionWithStatus(VerificationSessionStatus.COMPLETED),
                        sessionWithStatus(VerificationSessionStatus.COMPLETED),
                        sessionWithStatus(VerificationSessionStatus.FAILED),
                        sessionWithStatus(VerificationSessionStatus.IN_PROGRESS),
                        sessionWithStatus(VerificationSessionStatus.EXPIRED)
                ));

        Map<String, Object> stats = service.getVerificationStats(tenantId);

        assertThat(stats).containsEntry("total", 5L)
                .containsEntry("completed", 2L)
                .containsEntry("failed", 1L)
                .containsEntry("inProgress", 1L)
                .containsEntry("expired", 1L);
        assertThat((double) stats.get("successRate")).isEqualTo(0.4);
    }

    @Test
    @DisplayName("getVerificationStats with tenantId=null (SUPER_ADMIN) aggregates platform-wide")
    void statsPlatformWide() {
        when(sessionRepository.findAll()).thenReturn(List.of(
                sessionWithStatus(VerificationSessionStatus.COMPLETED)));

        Map<String, Object> stats = service.getVerificationStats(null);

        assertThat(stats).containsEntry("total", 1L);
        assertThat(stats.get("tenantId")).isNull();
    }

    @Test
    @DisplayName("getVerificationFlows filters to VERIFICATION flow type only")
    void flowsFilteredByType() {
        AuthFlow verify = AuthFlow.builder().id(UUID.randomUUID()).tenant(tenant)
                .name("KYC").flowType(FlowType.VERIFICATION).build();
        AuthFlow auth = AuthFlow.builder().id(UUID.randomUUID()).tenant(tenant)
                .name("Login").flowType(FlowType.AUTHENTICATION).build();
        when(authFlowRepository.findAllByTenantId(tenantId)).thenReturn(List.of(verify, auth));

        var flows = service.getVerificationFlows(tenantId);

        assertThat(flows).hasSize(1);
        assertThat(flows.get(0).name()).isEqualTo("KYC");
    }

    @Test
    @DisplayName("getVerificationFlows with null tenant → empty list")
    void flowsNullTenantReturnsEmpty() {
        assertThat(service.getVerificationFlows(null)).isEmpty();
    }

    @Test
    @DisplayName("listSessions with tenant scope → tenant-scoped repo")
    void listSessionsTenantScoped() {
        when(sessionRepository.findAllByTenantIdOrderByCreatedAtDesc(tenantId))
                .thenReturn(List.of(sessionWithStatus(VerificationSessionStatus.COMPLETED)));

        var sessions = service.listSessions(tenantId);

        assertThat(sessions).hasSize(1);
        assertThat(sessions.get(0).tenantId()).isEqualTo(tenantId);
    }
}
