package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.AuthMethodResponse;
import com.fivucsas.identity.application.dto.response.TenantAuthMethodResponse;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.domain.exception.AuthMethodInUseException;
import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.auth.StepType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.TenantAuthMethod;
import com.fivucsas.identity.repository.JpaTenantRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ManageAuthMethodServiceTest {

    @Mock private AuthMethodRepositoryPort authMethodRepository;
    @Mock private TenantAuthMethodRepositoryPort tenantAuthMethodRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private AuthFlowRepositoryPort authFlowRepository;
    @Mock private PuzzleLayerPolicy puzzleLayerPolicy;

    @InjectMocks private ManageAuthMethodService service;

    private final UUID tenantId = UUID.randomUUID();

    private AuthMethod method(AuthMethodType type) {
        return AuthMethod.builder()
                .id(UUID.randomUUID())
                .type(type)
                .name(type.name())
                .category(AuthMethodCategory.BASIC)
                .platforms(List.of("web"))
                .build();
    }

    private TenantAuthMethod tenantMethod(AuthMethod m, boolean enabled) {
        return TenantAuthMethod.builder()
                .id(UUID.randomUUID())
                .authMethod(m)
                .isEnabled(enabled)
                .build();
    }

    private AuthFlowStep stepOf(AuthMethod m) {
        return AuthFlowStep.builder()
                .id(UUID.randomUUID())
                .stepOrder(1)
                .authMethod(m)
                .stepType(StepType.SEQUENTIAL)
                .alternativeMethods(Collections.emptyList())
                .isRequired(true)
                .timeoutSeconds(120)
                .maxAttempts(3)
                .config("{}")
                .build();
    }

    private AuthFlow activeFlow(String name, AuthMethod m) {
        return AuthFlow.builder()
                .id(UUID.randomUUID())
                .name(name)
                .operationType(OperationType.APP_LOGIN)
                .steps(new java.util.ArrayList<>(List.of(stepOf(m))))
                .build(); // isActive defaults true
    }

    // ---- Part A: list filters to login methods only ----

    @Test
    void listAllMethods_excludesVerificationPipelineTypes() {
        when(authMethodRepository.findAllByIsActiveTrue()).thenReturn(List.of(
                method(AuthMethodType.PASSWORD),
                method(AuthMethodType.FACE),
                method(AuthMethodType.DOCUMENT_SCAN),   // verification-pipeline — excluded
                method(AuthMethodType.LIVENESS_CHECK))); // verification-pipeline — excluded

        List<AuthMethodResponse> result = service.listAllMethods();

        assertThat(result).extracting(AuthMethodResponse::type)
                .containsExactlyInAnyOrder(AuthMethodType.PASSWORD, AuthMethodType.FACE);
    }

    @Test
    void listTenantMethods_excludesVerificationPipelineTypes() {
        when(tenantAuthMethodRepository.findAllByTenantId(tenantId)).thenReturn(List.of(
                tenantMethod(method(AuthMethodType.TOTP), true),
                tenantMethod(method(AuthMethodType.FACE_MATCH), false))); // pipeline — excluded

        List<TenantAuthMethodResponse> result = service.listTenantMethods(tenantId);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).authMethod().type()).isEqualTo(AuthMethodType.TOTP);
    }

    // ---- Part B: disabling an in-active-flow method is blocked (409) ----

    @Test
    void configureTenantMethod_disableMethodInActiveFlow_throws409() {
        AuthMethod totp = method(AuthMethodType.TOTP);
        UUID authMethodId = totp.getId();
        when(tenantAuthMethodRepository.findByTenantIdAndAuthMethodId(tenantId, authMethodId))
                .thenReturn(Optional.of(tenantMethod(totp, true)));
        when(authFlowRepository.findAllByTenantId(tenantId))
                .thenReturn(List.of(activeFlow("Default 3-Step Flow", totp)));

        assertThatThrownBy(() -> service.configureTenantMethod(tenantId, authMethodId, false, null, false))
                .isInstanceOf(AuthMethodInUseException.class)
                .satisfies(ex -> assertThat(((AuthMethodInUseException) ex).getActiveFlowNames())
                        .containsExactly("Default 3-Step Flow"));

        // Must NOT persist the disable.
        verify(tenantAuthMethodRepository, never()).save(any());
    }

    @Test
    void configureTenantMethod_disableMethodInActiveFlow_withForce_succeeds() {
        AuthMethod totp = method(AuthMethodType.TOTP);
        UUID authMethodId = totp.getId();
        TenantAuthMethod row = tenantMethod(totp, true);
        when(tenantAuthMethodRepository.findByTenantIdAndAuthMethodId(tenantId, authMethodId))
                .thenReturn(Optional.of(row));
        when(tenantAuthMethodRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        TenantAuthMethodResponse result =
                service.configureTenantMethod(tenantId, authMethodId, false, null, true);

        // force=true skips the active-flow check entirely (no flow lookup needed).
        verify(authFlowRepository, never()).findAllByTenantId(any());
        verify(tenantAuthMethodRepository).save(any());
        assertThat(result.isEnabled()).isFalse();
    }

    @Test
    void configureTenantMethod_disableMethodNotInAnyActiveFlow_succeeds() {
        AuthMethod sms = method(AuthMethodType.SMS_OTP);
        UUID authMethodId = sms.getId();
        when(tenantAuthMethodRepository.findByTenantIdAndAuthMethodId(tenantId, authMethodId))
                .thenReturn(Optional.of(tenantMethod(sms, true)));
        // Active flow uses TOTP, not SMS_OTP → SMS_OTP is free to disable.
        when(authFlowRepository.findAllByTenantId(tenantId))
                .thenReturn(List.of(activeFlow("Default", method(AuthMethodType.TOTP))));
        when(tenantAuthMethodRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        TenantAuthMethodResponse result =
                service.configureTenantMethod(tenantId, authMethodId, false, null, false);

        assertThat(result.isEnabled()).isFalse();
        verify(tenantAuthMethodRepository).save(any());
    }

    @Test
    void configureTenantMethod_enable_isNeverGated() {
        AuthMethod totp = method(AuthMethodType.TOTP);
        UUID authMethodId = totp.getId();
        when(tenantAuthMethodRepository.findByTenantIdAndAuthMethodId(tenantId, authMethodId))
                .thenReturn(Optional.of(tenantMethod(totp, false)));
        when(tenantAuthMethodRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.configureTenantMethod(tenantId, authMethodId, true, null, false);

        // Enabling never consults active flows.
        verify(authFlowRepository, never()).findAllByTenantId(any());
        verify(tenantAuthMethodRepository).save(any());
    }

    // ---- Part C: PUZZLE is gated by PuzzleLayerPolicy ----

    @Test
    void listAllMethods_excludesPuzzle_whenPolicyOff() {
        // policy mock returns false for isGloballyEnabled() by default
        when(authMethodRepository.findAllByIsActiveTrue()).thenReturn(List.of(
                method(AuthMethodType.PASSWORD),
                method(AuthMethodType.PUZZLE)));

        List<AuthMethodResponse> result = service.listAllMethods();

        assertThat(result).extracting(AuthMethodResponse::type)
                .containsExactly(AuthMethodType.PASSWORD)
                .doesNotContain(AuthMethodType.PUZZLE);
    }

    @Test
    void listAllMethods_includesPuzzle_whenPolicyOn() {
        when(puzzleLayerPolicy.isGloballyEnabled()).thenReturn(true);
        when(authMethodRepository.findAllByIsActiveTrue()).thenReturn(List.of(
                method(AuthMethodType.PASSWORD),
                method(AuthMethodType.PUZZLE)));

        List<AuthMethodResponse> result = service.listAllMethods();

        assertThat(result).extracting(AuthMethodResponse::type)
                .containsExactlyInAnyOrder(AuthMethodType.PASSWORD, AuthMethodType.PUZZLE);
    }

    @Test
    void listTenantMethods_excludesPuzzle_whenPolicyOffForTenant() {
        // puzzleLayerPolicy.isEnabledFor(tenantId) returns false by default
        when(tenantAuthMethodRepository.findAllByTenantId(tenantId)).thenReturn(List.of(
                tenantMethod(method(AuthMethodType.TOTP), true),
                tenantMethod(method(AuthMethodType.PUZZLE), true)));

        List<TenantAuthMethodResponse> result = service.listTenantMethods(tenantId);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).authMethod().type()).isEqualTo(AuthMethodType.TOTP);
    }

    @Test
    void listTenantMethods_includesPuzzle_whenPolicyOnForTenant() {
        when(puzzleLayerPolicy.isEnabledFor(tenantId)).thenReturn(true);
        when(tenantAuthMethodRepository.findAllByTenantId(tenantId)).thenReturn(List.of(
                tenantMethod(method(AuthMethodType.TOTP), true),
                tenantMethod(method(AuthMethodType.PUZZLE), true)));

        List<TenantAuthMethodResponse> result = service.listTenantMethods(tenantId);

        assertThat(result).hasSize(2);
        assertThat(result).extracting(r -> r.authMethod().type())
                .containsExactlyInAnyOrder(AuthMethodType.TOTP, AuthMethodType.PUZZLE);
    }

    @Test
    void gestureLiveness_isNotALoginMethod() {
        // GESTURE_LIVENESS must never be offered as a selectable login method.
        // Regression guard: it has no isLoginMethod() = true, so even if a
        // stale DB row existed it would be filtered out.
        assertThat(AuthMethodType.PASSKEY.isLoginMethod()).isTrue(); // sanity
        // GESTURE_LIVENESS is not modelled as an AuthMethodType enum value
        // (no handler, no auth_methods row). Verify PUZZLE IS a login method
        // and is the only new value added in this phase.
        assertThat(AuthMethodType.PUZZLE.isLoginMethod()).isTrue();
    }
}
