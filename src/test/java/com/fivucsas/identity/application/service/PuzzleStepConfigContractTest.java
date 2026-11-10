package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthFlowStepRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.application.dto.command.UpdateAuthFlowCommand;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.domain.model.auth.PuzzleChallengeType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthMethod;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The PUZZLE step config has one accepted shape, {@code {"puzzleConfig":{...}}}.
 * Before this contract existed the web flow builder saved the inner object
 * without the {@code puzzleConfig} key, the api stored it verbatim, and both
 * readers (session create, the PUZZLE step handler) failed closed at login.
 */
@DisplayName("PUZZLE step config contract")
class PuzzleStepConfigContractTest {

    static final String WRAPPED =
            "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"BLINK\",\" Smile \"],"
            + "\"count\":2,\"difficulty\":\"medium\",\"alsoMatchFaceIdentity\":true}}";

    /** Exactly what the web flow builder wrote before the fix. */
    static final String FLAT_FROM_OLD_BUILDER =
            "{\"allowedChallengeTypes\":[\"blink\",\"smile\"],"
            + "\"count\":2,\"difficulty\":\"medium\",\"alsoMatchFaceIdentity\":true}";

    @Nested
    @DisplayName("PuzzleStepConfig.parse")
    class Parse {

        @Test
        void wrappedShape_parsesEveryField() {
            PuzzleStepConfig cfg = PuzzleStepConfig.parse(WRAPPED).orElseThrow();

            assertThat(cfg.allowedChallengeTypes()).containsExactly("blink", "smile");
            assertThat(cfg.count()).isEqualTo(2);
            assertThat(cfg.difficulty()).isEqualTo("medium");
            assertThat(cfg.alsoMatchFaceIdentity()).isTrue();
        }

        @Test
        void flatShape_isNotAPuzzleConfig() {
            assertThat(PuzzleStepConfig.parse(FLAT_FROM_OLD_BUILDER)).isEmpty();
        }

        @Test
        void missingBlankOrBrokenBlob_isEmpty() {
            assertThat(PuzzleStepConfig.parse(null)).isEmpty();
            assertThat(PuzzleStepConfig.parse(" ")).isEmpty();
            assertThat(PuzzleStepConfig.parse("{}")).isEmpty();
            assertThat(PuzzleStepConfig.parse("not json")).isEmpty();
        }

        @Test
        void emptyAllowList_stillParses_butHasNoChallenges() {
            // The binding flag must still be read (never weaken the identity gate).
            PuzzleStepConfig cfg = PuzzleStepConfig.parse(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[],\"alsoMatchFaceIdentity\":true}}")
                    .orElseThrow();

            assertThat(cfg.hasChallenges()).isFalse();
            assertThat(cfg.alsoMatchFaceIdentity()).isTrue();
        }

        @Test
        void missingOrInvalidFields_fallBackToTheSharedFailClosedDefaults() {
            // Same defaults as the web client (PUZZLE_CONFIG_DEFAULTS): binding ON, count 2.
            PuzzleStepConfig cfg = PuzzleStepConfig.parse(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"blink\"],\"count\":0}}").orElseThrow();

            assertThat(cfg.count()).isEqualTo(PuzzleStepConfig.DEFAULT_COUNT).isEqualTo(2);
            assertThat(cfg.difficulty()).isNull();
            assertThat(cfg.alsoMatchFaceIdentity())
                    .isEqualTo(PuzzleStepConfig.DEFAULT_ALSO_MATCH_FACE_IDENTITY).isTrue();

            PuzzleStepConfig notABoolean = PuzzleStepConfig.parse(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"blink\"],\"alsoMatchFaceIdentity\":\"no\"}}")
                    .orElseThrow();
            assertThat(notABoolean.alsoMatchFaceIdentity()).isTrue();
        }

        @Test
        void onlyAnExplicitFalse_turnsBindingOff() {
            assertThat(PuzzleStepConfig.parse(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"blink\"],\"alsoMatchFaceIdentity\":false}}")
                    .orElseThrow().alsoMatchFaceIdentity()).isFalse();
        }

        @Test
        void nonStringAllowListEntries_areDropped() {
            PuzzleStepConfig cfg = PuzzleStepConfig.parse(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[7,\"blink\",null,\" \"]}}").orElseThrow();

            assertThat(cfg.allowedChallengeTypes()).containsExactly("blink");
        }
    }

    @Nested
    @ExtendWith(MockitoExtension.class)
    @DisplayName("ManageAuthFlowService.createFlow guards the shape")
    class CreateFlowGuard {

        @Mock AuthFlowRepositoryPort authFlowRepository;
        @Mock AuthFlowStepRepositoryPort authFlowStepRepository;
        @Mock AuthMethodRepositoryPort authMethodRepository;
        @Mock JpaTenantRepository tenantRepository;
        @Mock TenantAuthMethodRepositoryPort tenantAuthMethodRepository;
        @Mock UserEnrollmentRepositoryPort userEnrollmentRepository;
        @Mock TenantAuthMethodPolicy tenantAuthMethodPolicy;
        @Mock UserRepository userRepository;

        private ManageAuthFlowService service() {
            return new ManageAuthFlowService(
                    authFlowRepository, authFlowStepRepository, authMethodRepository,
                    tenantRepository, tenantAuthMethodRepository, userEnrollmentRepository,
                    userRepository, tenantAuthMethodPolicy);
        }

        private CreateAuthFlowCommand flowWithPuzzleConfig(String config, List<String> alternatives,
                                                           String primary) {
            return new CreateAuthFlowCommand("Pilot A", null, OperationType.APP_LOGIN, false, List.of(
                    new CreateAuthFlowCommand.FlowStepSpec(
                            primary, 1, true, 120, 3, null, false, config, alternatives)));
        }

        private UUID stubTenant() {
            UUID tenantId = UUID.randomUUID();
            Tenant tenant = Tenant.builder().id(tenantId).name("Pilot").build();
            when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
            when(authFlowRepository.save(any())).thenReturn(AuthFlow.builder().id(UUID.randomUUID()).build());
            return tenantId;
        }

        @Test
        void puzzleStepWithTheOldFlatShape_isRejected() {
            UUID tenantId = stubTenant();

            assertThatThrownBy(() -> service().createFlow(tenantId,
                    flowWithPuzzleConfig(FLAT_FROM_OLD_BUILDER, null, "PUZZLE")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("puzzleConfig")
                    .hasMessageContaining("Layer 1");
            verify(authFlowStepRepository, never()).save(any());
        }

        @Test
        void puzzleStepWithAnEmptyAllowList_isRejected() {
            UUID tenantId = stubTenant();

            assertThatThrownBy(() -> service().createFlow(tenantId, flowWithPuzzleConfig(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[],\"count\":2}}", null, "PUZZLE")))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void puzzleStepWithoutConfig_isRejected() {
            UUID tenantId = stubTenant();

            assertThatThrownBy(() -> service().createFlow(tenantId,
                    flowWithPuzzleConfig(null, null, "PUZZLE")))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void puzzleOfferedAsAChoiceAlternative_isCheckedToo() {
            UUID tenantId = stubTenant();

            assertThatThrownBy(() -> service().createFlow(tenantId,
                    flowWithPuzzleConfig("{}", List.of("PUZZLE"), "FACE")))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void webRegistryIds_areRejected_becauseBioWouldRefuseTheSession() {
            // Exactly what the flow builder saved before web-app fixed B5.
            UUID tenantId = stubTenant();

            assertThatThrownBy(() -> service().createFlow(tenantId, flowWithPuzzleConfig(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"FACE_BLINK\",\"HAND_WAVE\",\"smile\"],"
                    + "\"count\":2}}", null, "PUZZLE")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("unknown challenge types")
                    .hasMessageContaining("face_blink")
                    .hasMessageContaining("hand_wave")
                    .hasMessageNotContaining("[smile")
                    .hasMessageContaining("Layer 1");
            verify(authFlowStepRepository, never()).save(any());
        }

        @Test
        void unknownTypeInAChoiceAlternative_isRejected() {
            UUID tenantId = stubTenant();

            assertThatThrownBy(() -> service().createFlow(tenantId, flowWithPuzzleConfig(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"object_match\"]}}",
                    List.of("PUZZLE"), "FACE")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("object_match");
        }

        @Test
        void everyBioChallengeType_isAccepted() {
            UUID tenantId = stubTenant();
            when(authMethodRepository.findByType(AuthMethodType.PUZZLE))
                    .thenReturn(Optional.of(AuthMethod.builder().type(AuthMethodType.PUZZLE).build()));
            when(authFlowRepository.findById(any())).thenReturn(Optional.of(AuthFlow.builder()
                    .id(UUID.randomUUID()).tenant(Tenant.builder().id(tenantId).name("Pilot").build())
                    .operationType(OperationType.APP_LOGIN).build()));
            String all = java.util.Arrays.stream(PuzzleChallengeType.values())
                    .map(t -> "\"" + t.wireValue() + "\"")
                    .collect(java.util.stream.Collectors.joining(","));

            service().createFlow(tenantId, flowWithPuzzleConfig(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[" + all + "],\"count\":2}}", null, "PUZZLE"));

            verify(authFlowStepRepository).save(any());
        }
    }

    @Nested
    @ExtendWith(MockitoExtension.class)
    @DisplayName("ManageAuthFlowService.updateFlow re-checks a stored flow joining the login surface")
    class UpdateFlowGuard {

        @Mock AuthFlowRepositoryPort authFlowRepository;
        @Mock AuthFlowStepRepositoryPort authFlowStepRepository;
        @Mock AuthMethodRepositoryPort authMethodRepository;
        @Mock JpaTenantRepository tenantRepository;
        @Mock TenantAuthMethodRepositoryPort tenantAuthMethodRepository;
        @Mock UserEnrollmentRepositoryPort userEnrollmentRepository;
        @Mock TenantAuthMethodPolicy tenantAuthMethodPolicy;
        @Mock UserRepository userRepository;

        private ManageAuthFlowService service() {
            return new ManageAuthFlowService(
                    authFlowRepository, authFlowStepRepository, authMethodRepository,
                    tenantRepository, tenantAuthMethodRepository, userEnrollmentRepository,
                    userRepository, tenantAuthMethodPolicy);
        }

        private AuthFlow storedPuzzleFlow(UUID tenantId, UUID flowId, String config) {
            AuthFlow flow = AuthFlow.builder().id(flowId)
                    .tenant(Tenant.builder().id(tenantId).name("Pilot").build())
                    .operationType(OperationType.APP_LOGIN).isActive(false).build();
            flow.getSteps().add(AuthFlowStep.builder()
                    .authFlow(flow)
                    .authMethod(AuthMethod.builder().type(AuthMethodType.PUZZLE).build())
                    .stepOrder(1)
                    .config(config)
                    .build());
            when(authFlowRepository.findByIdAndTenantId(flowId, tenantId)).thenReturn(Optional.of(flow));
            return flow;
        }

        @Test
        void activatingAStoredFlowWithRegistryIds_isRejected() {
            UUID tenantId = UUID.randomUUID();
            UUID flowId = UUID.randomUUID();
            storedPuzzleFlow(tenantId, flowId,
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"FACE_BLINK\"]}}");

            assertThatThrownBy(() -> service().updateFlow(tenantId, flowId,
                    new UpdateAuthFlowCommand(null, null, null, true)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("face_blink");
            verify(authFlowRepository, never()).save(any());
        }

        @Test
        void makingAStoredFlowDefault_withAValidConfig_isAllowed() {
            UUID tenantId = UUID.randomUUID();
            UUID flowId = UUID.randomUUID();
            AuthFlow flow = storedPuzzleFlow(tenantId, flowId,
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"blink\",\"wave\"],\"count\":2}}");
            when(authFlowRepository.save(flow)).thenReturn(flow);

            service().updateFlow(tenantId, flowId, new UpdateAuthFlowCommand(null, null, true, null));

            verify(authFlowRepository).save(flow);
        }

        @Test
        void renamingOnly_doesNotRecheck() {
            UUID tenantId = UUID.randomUUID();
            UUID flowId = UUID.randomUUID();
            AuthFlow flow = storedPuzzleFlow(tenantId, flowId,
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"FACE_BLINK\"]}}");
            when(authFlowRepository.save(flow)).thenReturn(flow);

            service().updateFlow(tenantId, flowId, new UpdateAuthFlowCommand("Renamed", null, null, null));

            verify(authFlowRepository).save(flow);
        }
    }

    @Nested
    @DisplayName("PuzzleChallengeType (bio's ChallengeType wire values)")
    class ChallengeTypes {

        @Test
        void matchesBiosChallengeTypeSet() {
            // bio app/api/schemas/active_liveness.py ChallengeType, f0d1f71 / 9a86866.
            assertThat(java.util.Arrays.stream(PuzzleChallengeType.values()).map(PuzzleChallengeType::wireValue))
                    .containsExactlyInAnyOrder(
                            "blink", "smile", "light", "turn_left", "turn_right", "open_mouth",
                            "raise_eyebrows", "close_left_eye", "close_right_eye", "look_up", "look_down",
                            "raise_left_brow", "raise_right_brow", "nod", "shake_head",
                            "finger_count", "shape_trace", "wave", "hand_flip", "finger_tap", "pinch",
                            "peek_a_boo", "math", "hold_position");
        }

        @Test
        void fromWire_isTrimmedAndCaseInsensitive_andRejectsRegistryIds() {
            assertThat(PuzzleChallengeType.fromWire(" Blink ")).contains(PuzzleChallengeType.BLINK);
            assertThat(PuzzleChallengeType.isKnown("FACE_BLINK")).isFalse();
            assertThat(PuzzleChallengeType.isKnown(null)).isFalse();
        }
    }
}
