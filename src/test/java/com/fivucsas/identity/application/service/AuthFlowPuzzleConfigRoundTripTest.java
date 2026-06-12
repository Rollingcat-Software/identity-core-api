package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.dto.response.AuthFlowStepResponse;
import com.fivucsas.identity.application.dto.response.LoginConfigResponse;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthFlowStepRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodCategory;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.tenant.Tenant;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Task 2.4 — puzzle-layer config round-trip.
 *
 * <p>Verifies that:
 * <ol>
 *   <li>A PUZZLE step's {@code puzzleConfig} JSON blob persists through
 *       {@link ManageAuthFlowService#createFlow} and is returned in
 *       {@link AuthFlowStepResponse#config()}.</li>
 *   <li>A FACE step's {@code requireActivePuzzleLiveness} blob persists
 *       identically.</li>
 *   <li>{@link LoginConfigService#getLoginConfig} surfaces the step-level
 *       {@code stepConfig} JSON in {@link LoginConfigResponse.Layer1} and
 *       {@link LoginConfigResponse.LaterStep} so the runtime/frontend can read
 *       {@code puzzleConfig} / {@code requireActivePuzzleLiveness}.</li>
 * </ol>
 */
@DisplayName("Task 2.4 — puzzle-layer config round-trip")
class AuthFlowPuzzleConfigRoundTripTest {

    static final String PUZZLE_CONFIG =
            "{\"allowedChallengeTypes\":[\"OBJECT_MATCH\",\"COUNT\"],"
            + "\"count\":3,\"difficulty\":\"medium\",\"alsoMatchFaceIdentity\":false}";

    static final String FACE_CONFIG =
            "{\"requireActivePuzzleLiveness\":true}";

    static AuthMethod authMethod(AuthMethodType type) {
        return AuthMethod.builder()
                .id(UUID.randomUUID())
                .type(type)
                .name(type.name())
                .category(AuthMethodCategory.BASIC)
                .platforms(List.of("WEB"))
                .requiresEnrollment(true)
                .supportsUsernameless(false)
                .isActive(true)
                .build();
    }

    // ════════════════════════════════════════════════════════════════════════
    // 1. Create-path: FlowStepSpec.config persisted and returned via
    //    AuthFlowStepResponse.config()
    // ════════════════════════════════════════════════════════════════════════

    @Nested
    @ExtendWith(MockitoExtension.class)
    @DisplayName("ManageAuthFlowService — step config persisted through createFlow")
    class CreateFlowConfigRoundTrip {

        @Mock AuthFlowRepositoryPort authFlowRepository;
        @Mock AuthFlowStepRepositoryPort authFlowStepRepository;
        @Mock AuthMethodRepositoryPort authMethodRepository;
        @Mock JpaTenantRepository tenantRepository;
        @Mock TenantAuthMethodRepositoryPort tenantAuthMethodRepository;
        @Mock UserEnrollmentRepositoryPort userEnrollmentRepository;
        @Mock TenantAuthMethodPolicy tenantAuthMethodPolicy;
        @Mock UserRepository userRepository;

        @Test
        @DisplayName("PUZZLE + FACE step configs round-trip through createFlow → getFlow")
        void puzzleAndFaceConfigRoundTrip() {
            UUID tenantId = UUID.randomUUID();
            UUID flowId = UUID.randomUUID();

            com.fivucsas.identity.entity.Tenant tenantEntity =
                    com.fivucsas.identity.entity.Tenant.builder().id(tenantId).name("Test").build();
            AuthMethod puzzleMethod = authMethod(AuthMethodType.PUZZLE);
            AuthMethod faceMethod   = authMethod(AuthMethodType.FACE);

            // The saved flow returns real step entities so AuthFlowResponse.from() works.
            AuthFlowStep puzzleStep = AuthFlowStep.builder()
                    .id(UUID.randomUUID())
                    .authMethod(puzzleMethod)
                    .stepOrder(1)
                    .isRequired(true)
                    .config(PUZZLE_CONFIG)
                    .build();
            AuthFlowStep faceStep = AuthFlowStep.builder()
                    .id(UUID.randomUUID())
                    .authMethod(faceMethod)
                    .stepOrder(2)
                    .isRequired(true)
                    .config(FACE_CONFIG)
                    .build();

            AuthFlow savedFlow = AuthFlow.builder()
                    .id(flowId)
                    .tenant(tenantEntity)
                    .name("Puzzle+Face Flow")
                    .operationType(OperationType.APP_LOGIN)
                    .isDefault(false)
                    .isActive(true)
                    .steps(new ArrayList<>(List.of(puzzleStep, faceStep)))
                    .build();

            when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenantEntity));
            when(authFlowRepository.save(any())).thenReturn(savedFlow);
            when(authFlowRepository.findById(flowId)).thenReturn(Optional.of(savedFlow));
            when(authMethodRepository.findByType(AuthMethodType.PUZZLE))
                    .thenReturn(Optional.of(puzzleMethod));
            when(authMethodRepository.findByType(AuthMethodType.FACE))
                    .thenReturn(Optional.of(faceMethod));

            ManageAuthFlowService service = new ManageAuthFlowService(
                    authFlowRepository, authFlowStepRepository, authMethodRepository,
                    tenantRepository, tenantAuthMethodRepository, userEnrollmentRepository,
                    userRepository, tenantAuthMethodPolicy);

            var steps = List.of(
                    new CreateAuthFlowCommand.FlowStepSpec(
                            "PUZZLE", 1, true, 120, 3, null, true, PUZZLE_CONFIG, null),
                    new CreateAuthFlowCommand.FlowStepSpec(
                            "FACE",   2, true, 120, 3, null, true, FACE_CONFIG,   null)
            );
            AuthFlowResponse response = service.createFlow(tenantId,
                    new CreateAuthFlowCommand("Puzzle+Face", null, OperationType.APP_LOGIN, false, steps));

            // PUZZLE step config must round-trip faithfully
            AuthFlowStepResponse puzzleResp = response.steps().stream()
                    .filter(s -> "PUZZLE".equals(s.authMethodType()))
                    .findFirst().orElseThrow();
            assertThat(puzzleResp.config())
                    .as("PUZZLE step config must round-trip faithfully")
                    .isEqualTo(PUZZLE_CONFIG);

            // FACE step config must round-trip faithfully
            AuthFlowStepResponse faceResp = response.steps().stream()
                    .filter(s -> "FACE".equals(s.authMethodType()))
                    .findFirst().orElseThrow();
            assertThat(faceResp.config())
                    .as("FACE step config (requireActivePuzzleLiveness) must round-trip faithfully")
                    .isEqualTo(FACE_CONFIG);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // 2. LoginConfigService surfaces stepConfig in Layer1 and LaterStep
    // ════════════════════════════════════════════════════════════════════════

    @Nested
    @ExtendWith(MockitoExtension.class)
    @DisplayName("LoginConfigService — stepConfig surfaced in login-config response")
    class LoginConfigStepConfig {

        @Mock AuthFlowRepositoryPort authFlowRepository;
        @Mock TenantRepository domainTenantRepository;
        @Mock OAuth2ClientRepositoryPort oAuth2ClientRepository;
        @Mock ConfigDrivenLoginPolicy configDrivenLoginPolicy;

        @Test
        @DisplayName("getLoginConfig surfaces PUZZLE stepConfig in Layer1 and FACE stepConfig in LaterStep")
        void loginConfigSurfacesStepConfig() {
            UUID tenantId = UUID.randomUUID();

            AuthMethod puzzleMethod = authMethod(AuthMethodType.PUZZLE);
            AuthMethod faceMethod   = authMethod(AuthMethodType.FACE);

            AuthFlowStep puzzleStep = AuthFlowStep.builder()
                    .id(UUID.randomUUID())
                    .authMethod(puzzleMethod)
                    .stepOrder(1)
                    .isRequired(true)
                    .config(PUZZLE_CONFIG)
                    .build();
            AuthFlowStep faceStep = AuthFlowStep.builder()
                    .id(UUID.randomUUID())
                    .authMethod(faceMethod)
                    .stepOrder(2)
                    .isRequired(true)
                    .config(FACE_CONFIG)
                    .build();

            com.fivucsas.identity.entity.Tenant tenantEntity =
                    com.fivucsas.identity.entity.Tenant.builder().id(tenantId).name("Acme").build();
            AuthFlow flow = AuthFlow.builder()
                    .id(UUID.randomUUID())
                    .tenant(tenantEntity)
                    .name("Puzzle+Face")
                    .operationType(OperationType.APP_LOGIN)
                    .isDefault(true).isActive(true)
                    .steps(new ArrayList<>(List.of(puzzleStep, faceStep)))
                    .build();

            when(configDrivenLoginPolicy.isEnabledFor(tenantId)).thenReturn(true);
            // Use a Tenant.reconstitute with required non-null fields
            when(domainTenantRepository.findById(tenantId))
                    .thenReturn(Optional.of(Tenant.reconstitute(
                            tenantId, "Acme", "acme", null,
                            "ops@acme.test", null, null, null, null, null)));
            when(authFlowRepository
                    .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                            tenantId, OperationType.APP_LOGIN))
                    .thenReturn(Optional.of(flow));

            LoginConfigService loginConfigService = new LoginConfigService(
                    authFlowRepository,
                    domainTenantRepository,
                    oAuth2ClientRepository,
                    configDrivenLoginPolicy);

            LoginConfigResponse cfg = loginConfigService.getLoginConfig(tenantId);

            // Layer-1 (PUZZLE step): stepConfig must be the puzzleConfig blob
            assertThat(cfg.layer1().stepConfig())
                    .as("Layer1 must carry the PUZZLE stepConfig")
                    .isEqualTo(PUZZLE_CONFIG);

            // Later step (FACE step): stepConfig must be the face config blob
            assertThat(cfg.laterSteps()).hasSize(1);
            assertThat(cfg.laterSteps().get(0).stepConfig())
                    .as("LaterStep must carry the FACE stepConfig (requireActivePuzzleLiveness)")
                    .isEqualTo(FACE_CONFIG);
        }

        @Test
        @DisplayName("step with default empty config '{}' yields null stepConfig (no noise in response)")
        void emptyStepConfigYieldsNull() {
            UUID tenantId = UUID.randomUUID();

            AuthMethod passwordMethod = authMethod(AuthMethodType.PASSWORD);

            AuthFlowStep step = AuthFlowStep.builder()
                    .id(UUID.randomUUID())
                    .authMethod(passwordMethod)
                    .stepOrder(1)
                    .isRequired(true)
                    .config("{}")   // default / empty config
                    .build();

            com.fivucsas.identity.entity.Tenant tenantEntity =
                    com.fivucsas.identity.entity.Tenant.builder().id(tenantId).name("Acme").build();
            AuthFlow flow = AuthFlow.builder()
                    .id(UUID.randomUUID())
                    .tenant(tenantEntity)
                    .name("Single-step")
                    .operationType(OperationType.APP_LOGIN)
                    .isDefault(true).isActive(true)
                    .steps(new ArrayList<>(List.of(step)))
                    .build();

            when(configDrivenLoginPolicy.isEnabledFor(tenantId)).thenReturn(true);
            when(domainTenantRepository.findById(tenantId))
                    .thenReturn(Optional.of(Tenant.reconstitute(
                            tenantId, "Acme", "acme", null,
                            "ops@acme.test", null, null, null, null, null)));
            when(authFlowRepository
                    .findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                            tenantId, OperationType.APP_LOGIN))
                    .thenReturn(Optional.of(flow));

            LoginConfigService loginConfigService = new LoginConfigService(
                    authFlowRepository,
                    domainTenantRepository,
                    oAuth2ClientRepository,
                    configDrivenLoginPolicy);

            LoginConfigResponse cfg = loginConfigService.getLoginConfig(tenantId);

            assertThat(cfg.layer1().stepConfig())
                    .as("empty config '{}' must yield null stepConfig (no noise in response)")
                    .isNull();
        }
    }
}
