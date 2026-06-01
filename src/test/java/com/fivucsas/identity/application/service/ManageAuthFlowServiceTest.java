package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthFlowStepRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.domain.model.auth.StepType;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ManageAuthFlowServiceTest {

    @Mock private AuthFlowRepositoryPort authFlowRepository;
    @Mock private AuthFlowStepRepositoryPort authFlowStepRepository;
    @Mock private AuthMethodRepositoryPort authMethodRepository;
    @Mock private JpaTenantRepository tenantRepository;
    @Mock private TenantAuthMethodRepositoryPort tenantAuthMethodRepository;
    // Default mock returns false for the boolean isLoginMethodExplicitlyDisabled
    // → "not disabled / allowed", so the happy-path tests above keep passing
    // without a stub. The dedicated test below overrides it.
    @Mock private TenantAuthMethodPolicy tenantAuthMethodPolicy;

    @InjectMocks
    private ManageAuthFlowService service;

    @Test
    void createFlow_WhenAppLoginWithFaceFirst_ShouldSucceed() {
        // After removing the PASSWORD-first constraint (2026-04-24) tenants can
        // configure APP_LOGIN flows that start with any AuthMethod (e.g. FACE).
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod faceMethod = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getName()).thenReturn("Face-First Login");
        when(flow.getDescription()).thenReturn("desc");
        when(flow.getOperationType()).thenReturn(OperationType.APP_LOGIN);
        when(flow.isDefault()).thenReturn(false);
        when(flow.isActive()).thenReturn(true);
        when(flow.getStepCount()).thenReturn(0);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.FACE)).thenReturn(Optional.of(faceMethod));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "FACE", 1, true, 120, 3, null, false, null, null
                )
        );
        var command = new CreateAuthFlowCommand("Face-First Login", "desc", OperationType.APP_LOGIN, false, steps);

        service.createFlow(tenantId, command);

        verify(authFlowStepRepository).save(any());
    }

    @Test
    void createFlow_WhenLayerHasMultipleMethods_ShouldPersistAsChoiceWithFullSet() {
        // Method-set model: a layer with >1 allowed method is a CHOICE — the user
        // satisfies it with ANY ONE. We store the full set (primary first) in
        // alternativeMethods + stepType=CHOICE so the login engine accepts either.
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod password = mock(AuthMethod.class);
        AuthMethod emailOtp = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getName()).thenReturn("Choice");
        when(flow.getOperationType()).thenReturn(OperationType.APP_LOGIN);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.PASSWORD)).thenReturn(Optional.of(password));
        when(authMethodRepository.findByType(AuthMethodType.EMAIL_OTP)).thenReturn(Optional.of(emailOtp));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "PASSWORD", 1, true, 120, 3, null, false, null, List.of("EMAIL_OTP")
                )
        );
        service.createFlow(tenantId,
                new CreateAuthFlowCommand("Choice", "", OperationType.APP_LOGIN, false, steps));

        ArgumentCaptor<AuthFlowStep> captor = ArgumentCaptor.forClass(AuthFlowStep.class);
        verify(authFlowStepRepository).save(captor.capture());
        AuthFlowStep saved = captor.getValue();
        assertThat(saved.getStepType()).isEqualTo(StepType.CHOICE);
        assertThat(saved.getAlternativeMethods()).containsExactly(password, emailOtp);
    }

    @Test
    void createFlow_RequiredChoiceWithSupportedAlternative_ShouldSucceed() {
        // A required layer offering {VOICE, EMAIL_OTP} is fine — VOICE can't stand
        // alone as required, but EMAIL_OTP gives the user a supported way to satisfy
        // the layer, so the choice must be allowed (regression: it used to 400 on
        // the VOICE primary).
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.VOICE)).thenReturn(Optional.of(mock(AuthMethod.class)));
        when(authMethodRepository.findByType(AuthMethodType.EMAIL_OTP)).thenReturn(Optional.of(mock(AuthMethod.class)));

        var steps = List.of(new CreateAuthFlowCommand.FlowStepSpec(
                "VOICE", 1, true, 120, 3, null, false, null, List.of("EMAIL_OTP")));
        service.createFlow(tenantId,
                new CreateAuthFlowCommand("Voice-or-Email", "", OperationType.APP_LOGIN, false, steps));

        verify(authFlowStepRepository).save(any());
    }

    @Test
    void createFlow_RequiredLayerOnlyUnsupportedMethods_ShouldReject() {
        // A required layer whose ONLY method is VOICE has no supported way to be
        // completed → still rejected (400).
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        var steps = List.of(new CreateAuthFlowCommand.FlowStepSpec(
                "VOICE", 1, true, 120, 3, null, false, null, null));
        assertThatThrownBy(() -> service.createFlow(tenantId,
                new CreateAuthFlowCommand("Voice-only", "", OperationType.APP_LOGIN, false, steps)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void createFlow_WhenNoPasswordAnywhere_ShouldSucceed() {
        // Two-step FACE -> TOTP flow, no PASSWORD anywhere — explicitly
        // supported by the new customizable-auth-flow model.
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod faceMethod = mock(AuthMethod.class);
        AuthMethod totpMethod = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getName()).thenReturn("Passwordless Login");
        when(flow.getDescription()).thenReturn("desc");
        when(flow.getOperationType()).thenReturn(OperationType.APP_LOGIN);
        when(flow.isDefault()).thenReturn(false);
        when(flow.isActive()).thenReturn(true);
        when(flow.getStepCount()).thenReturn(0);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.FACE)).thenReturn(Optional.of(faceMethod));
        when(authMethodRepository.findByType(AuthMethodType.TOTP)).thenReturn(Optional.of(totpMethod));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "FACE", 1, true, 120, 3, null, false, null, null
                ),
                new CreateAuthFlowCommand.FlowStepSpec(
                        "TOTP", 2, true, 120, 3, null, false, null, null
                )
        );
        var command = new CreateAuthFlowCommand("Passwordless Login", "desc", OperationType.APP_LOGIN, false, steps);

        service.createFlow(tenantId, command);

        verify(authFlowStepRepository, times(2)).save(any());
    }

    @Test
    void createFlow_WhenAppLoginWithPasswordFirst_ShouldSucceed() {
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod passwordMethod = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getName()).thenReturn("Login Flow");
        when(flow.getDescription()).thenReturn("desc");
        when(flow.getOperationType()).thenReturn(OperationType.APP_LOGIN);
        when(flow.isDefault()).thenReturn(false);
        when(flow.isActive()).thenReturn(true);
        when(flow.getStepCount()).thenReturn(0);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.PASSWORD)).thenReturn(Optional.of(passwordMethod));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "PASSWORD", 1, true, 120, 3, null, false, null, null
                )
        );
        var command = new CreateAuthFlowCommand("Login Flow", "desc", OperationType.APP_LOGIN, false, steps);

        service.createFlow(tenantId, command);

        verify(authFlowStepRepository).save(any());
    }

    @Test
    void createFlow_WhenDoorAccessWithoutPassword_ShouldSucceed() {
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod faceMethod = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getName()).thenReturn("Door Flow");
        when(flow.getDescription()).thenReturn("desc");
        when(flow.getOperationType()).thenReturn(OperationType.DOOR_ACCESS);
        when(flow.isDefault()).thenReturn(false);
        when(flow.isActive()).thenReturn(true);
        when(flow.getStepCount()).thenReturn(0);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.FACE)).thenReturn(Optional.of(faceMethod));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "FACE", 1, true, 120, 3, null, false, null, null
                )
        );
        var command = new CreateAuthFlowCommand("Door Flow", "desc", OperationType.DOOR_ACCESS, false, steps);

        service.createFlow(tenantId, command);

        verify(authFlowStepRepository).save(any());
    }

    @Test
    void createFlow_WhenApiAccessWithTotpFirst_ShouldSucceed() {
        // API_ACCESS no longer requires PASSWORD-first — TOTP as step[0] is valid.
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        AuthMethod totpMethod = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getName()).thenReturn("API Flow");
        when(flow.getDescription()).thenReturn("desc");
        when(flow.getOperationType()).thenReturn(OperationType.API_ACCESS);
        when(flow.isDefault()).thenReturn(false);
        when(flow.isActive()).thenReturn(true);
        when(flow.getStepCount()).thenReturn(0);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.TOTP)).thenReturn(Optional.of(totpMethod));

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "TOTP", 1, true, 120, 3, null, false, null, null
                )
        );
        var command = new CreateAuthFlowCommand("API Flow", "desc", OperationType.API_ACCESS, false, steps);

        service.createFlow(tenantId, command);

        verify(authFlowStepRepository).save(any());
    }

    @Test
    void createFlow_WhenDefaultRequestedAndAnotherDefaultExists_ShouldDethroneIncumbentFirst() {
        // Regression (prod 2026-05-31, fivucsas tenant): creating a NEW is_default
        // flow while another flow already held the (tenant, APP_LOGIN) default slot
        // hit the partial unique index uq_auth_flow_default → 23505 → opaque 500 on
        // the Auth Flows page. createFlow must dethrone the incumbent (saveAndFlush,
        // freeing the slot per-statement) BEFORE inserting the new default — the
        // same fix updateFlow already had (PR #115).
        UUID tenantId = UUID.randomUUID();
        UUID flowId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(tenantId);
        AuthFlow flow = mock(AuthFlow.class);
        AuthFlow incumbent = mock(AuthFlow.class);
        AuthMethod password = mock(AuthMethod.class);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(flow.getId()).thenReturn(flowId);
        when(flow.getTenant()).thenReturn(tenant);
        when(flow.getName()).thenReturn("New Default");
        when(flow.getDescription()).thenReturn("");
        when(flow.getOperationType()).thenReturn(OperationType.APP_LOGIN);
        when(flow.isDefault()).thenReturn(true);
        when(flow.isActive()).thenReturn(true);
        when(flow.getStepCount()).thenReturn(1);
        when(flow.getSteps()).thenReturn(new ArrayList<>());
        when(flow.getCreatedAt()).thenReturn(Instant.now());
        when(flow.getUpdatedAt()).thenReturn(Instant.now());
        when(incumbent.isDefault()).thenReturn(true);
        when(authFlowRepository.findAllByTenantIdAndOperationType(tenantId, OperationType.APP_LOGIN))
                .thenReturn(List.of(incumbent));
        when(authFlowRepository.save(any())).thenReturn(flow);
        when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(flow));
        when(authMethodRepository.findByType(AuthMethodType.PASSWORD)).thenReturn(Optional.of(password));

        var steps = List.of(new CreateAuthFlowCommand.FlowStepSpec(
                "PASSWORD", 1, true, 120, 3, null, false, null, null));
        service.createFlow(tenantId,
                new CreateAuthFlowCommand("New Default", "", OperationType.APP_LOGIN, true, steps));

        verify(incumbent).unsetDefault();
        verify(authFlowRepository).saveAndFlush(incumbent);
    }

    @Test
    void createFlow_WhenStepMethodDisabledForTenant_ShouldReject422() {
        // No-lock-out guard (write side): a flow that references a method
        // EXPLICITLY disabled for the tenant must be refused so login
        // enforcement can never block a method an active flow demands.
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.save(any())).thenReturn(AuthFlow.builder()
                .tenant(tenant).name("Has-Disabled").operationType(OperationType.APP_LOGIN).build());
        // TOTP is disabled for this tenant; PASSWORD (the other referenced
        // method) is allowed. lenient() because the validation also probes
        // PASSWORD and the probe order isn't contractual.
        lenient().when(tenantAuthMethodPolicy.isLoginMethodExplicitlyDisabled(tenantId, AuthMethodType.TOTP))
                .thenReturn(true);
        lenient().when(tenantAuthMethodPolicy.isLoginMethodExplicitlyDisabled(tenantId, AuthMethodType.PASSWORD))
                .thenReturn(false);

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "PASSWORD", 1, true, 120, 3, null, false, null, null),
                new CreateAuthFlowCommand.FlowStepSpec(
                        "TOTP", 2, true, 120, 3, null, false, null, null));
        var command = new CreateAuthFlowCommand("Has-Disabled", "", OperationType.APP_LOGIN, false, steps);

        assertThatThrownBy(() -> service.createFlow(tenantId, command))
                .isInstanceOf(com.fivucsas.identity.domain.exception.AuthFlowMethodDisabledException.class);
        // The flow's steps are never persisted when a disabled method is present.
        verify(authFlowStepRepository, never()).save(any());
    }

    @Test
    void createFlow_WhenNoStepOneDefined_ShouldThrow() {
        // Structural check still in force: must define stepOrder=1.
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.save(any())).thenReturn(AuthFlow.builder()
                .tenant(tenant).name("test").operationType(OperationType.APP_LOGIN).build());

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "PASSWORD", 2, true, 120, 3, null, false, null, null
                )
        );
        var command = new CreateAuthFlowCommand("Broken", "desc", OperationType.APP_LOGIN, false, steps);

        assertThatThrownBy(() -> service.createFlow(tenantId, command))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("stepOrder=1");
    }

    @Test
    void createFlow_WhenDuplicateStepOrders_ShouldThrow() {
        // Structural check: stepOrder values must be unique across the flow.
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = mock(Tenant.class);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(authFlowRepository.save(any())).thenReturn(AuthFlow.builder()
                .tenant(tenant).name("test").operationType(OperationType.APP_LOGIN).build());

        var steps = List.of(
                new CreateAuthFlowCommand.FlowStepSpec(
                        "PASSWORD", 1, true, 120, 3, null, false, null, null
                ),
                new CreateAuthFlowCommand.FlowStepSpec(
                        "TOTP", 1, true, 120, 3, null, false, null, null
                )
        );
        var command = new CreateAuthFlowCommand("Broken", "desc", OperationType.APP_LOGIN, false, steps);

        assertThatThrownBy(() -> service.createFlow(tenantId, command))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("multiple steps with stepOrder=1");
    }
}
