package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.LoginConfigResponse;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("LoginConfigService — public tenant login-flow config (task #16 C)")
class LoginConfigServiceTest {

    @Mock private AuthFlowRepositoryPort authFlowRepository;
    @Mock private TenantRepository tenantRepository;

    @InjectMocks private LoginConfigService service;

    private AuthMethod method(AuthMethodType type, boolean requiresEnrollment, boolean usernameless) {
        return AuthMethod.builder()
                .id(UUID.randomUUID())
                .type(type)
                .name(type.name())
                .category(AuthMethodCategory.BASIC)
                .platforms(List.of("WEB"))
                .requiresEnrollment(requiresEnrollment)
                .supportsUsernameless(usernameless)
                .build();
    }

    private AuthFlowStep step(int order, AuthMethod m) {
        return AuthFlowStep.builder()
                .id(UUID.randomUUID())
                .stepOrder(order)
                .authMethod(m)
                .isRequired(true)
                .build();
    }

    private AuthFlow flow(UUID tenantId, AuthFlowStep... steps) {
        com.fivucsas.identity.entity.Tenant tenant = com.fivucsas.identity.entity.Tenant.builder()
                .id(tenantId).name("Acme").build();
        return AuthFlow.builder()
                .id(UUID.randomUUID())
                .tenant(tenant)
                .name("Login")
                .operationType(OperationType.APP_LOGIN)
                .isDefault(true).isActive(true)
                .steps(new ArrayList<>(List.of(steps)))
                .build();
    }

    @Test
    @DisplayName("No default flow → implicit single-step PASSWORD, identifierRequired=true")
    void noFlowFallsBackToPassword() {
        UUID tenantId = UUID.randomUUID();
        when(tenantRepository.findById(tenantId))
                .thenReturn(Optional.of(Tenant.reconstitute(tenantId, "Acme", "acme", "desc",
                        "ops@acme.test", "+10000000000", null, null, null, null)));
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                eq(tenantId), eq(OperationType.APP_LOGIN))).thenReturn(Optional.empty());

        LoginConfigResponse cfg = service.getLoginConfig(tenantId);

        assertThat(cfg.tenantId()).isEqualTo(tenantId.toString());
        assertThat(cfg.tenantName()).isEqualTo("Acme");
        assertThat(cfg.totalSteps()).isEqualTo(1);
        assertThat(cfg.layer1().identifierRequired()).isTrue();
        assertThat(cfg.layer1().methods()).singleElement()
                .satisfies(m -> {
                    assertThat(m.type()).isEqualTo("PASSWORD");
                    assertThat(m.usernameless()).isFalse();
                });
        assertThat(cfg.laterSteps()).isEmpty();
    }

    @Test
    @DisplayName("Usernameless-only Layer-1 (PASSKEY) → identifierRequired=false; no internal IDs leaked")
    void usernamelessLayer1NotIdentifierRequired() {
        UUID tenantId = UUID.randomUUID();
        AuthMethod passkey = method(AuthMethodType.PASSKEY, true, true);
        AuthMethod emailOtp = method(AuthMethodType.EMAIL_OTP, false, false);
        when(tenantRepository.findById(any())).thenReturn(Optional.empty());
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                eq(tenantId), eq(OperationType.APP_LOGIN)))
                .thenReturn(Optional.of(flow(tenantId, step(1, passkey), step(2, emailOtp))));

        LoginConfigResponse cfg = service.getLoginConfig(tenantId);

        assertThat(cfg.totalSteps()).isEqualTo(2);
        assertThat(cfg.layer1().identifierRequired()).isFalse();
        assertThat(cfg.layer1().methods()).singleElement().satisfies(m -> {
            assertThat(m.type()).isEqualTo("PASSKEY");
            assertThat(m.usernameless()).isTrue();
            assertThat(m.requiresEnrollment()).isTrue();
        });
        assertThat(cfg.laterSteps()).singleElement().satisfies(s -> {
            assertThat(s.order()).isEqualTo(2);
            assertThat(s.methods()).singleElement()
                    .satisfies(m -> assertThat(m.type()).isEqualTo("EMAIL_OTP"));
        });
    }

    @Test
    @DisplayName("PASSWORD Layer-1 → identifierRequired=true")
    void passwordLayer1IsIdentifierRequired() {
        UUID tenantId = UUID.randomUUID();
        AuthMethod password = method(AuthMethodType.PASSWORD, true, false);
        when(tenantRepository.findById(any())).thenReturn(Optional.empty());
        when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                eq(tenantId), eq(OperationType.APP_LOGIN)))
                .thenReturn(Optional.of(flow(tenantId, step(1, password))));

        LoginConfigResponse cfg = service.getLoginConfig(tenantId);

        assertThat(cfg.layer1().identifierRequired()).isTrue();
        assertThat(cfg.totalSteps()).isEqualTo(1);
        assertThat(cfg.laterSteps()).isEmpty();
    }
}
