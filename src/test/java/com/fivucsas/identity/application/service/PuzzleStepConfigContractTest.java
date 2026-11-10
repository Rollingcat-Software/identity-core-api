package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateAuthFlowCommand;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthFlowStepRepositoryPort;
import com.fivucsas.identity.application.port.output.AuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;
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
        void countBelowOne_andMissingBinding_fallBackToSafeDefaults() {
            PuzzleStepConfig cfg = PuzzleStepConfig.parse(
                    "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"blink\"],\"count\":0}}").orElseThrow();

            assertThat(cfg.count()).isEqualTo(1);
            assertThat(cfg.difficulty()).isNull();
            assertThat(cfg.alsoMatchFaceIdentity()).isFalse();
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
    }
}
