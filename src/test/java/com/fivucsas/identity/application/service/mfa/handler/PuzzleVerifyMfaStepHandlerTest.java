package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Server-authoritative re-score tests for {@link PuzzleVerifyMfaStepHandler}
 * (Task 3.3, sub-project B).
 *
 * <p>The crux: a PUZZLE step passes ONLY because the SERVER (biometric-processor
 * {@code /liveness/verify-challenge}) re-scored EVERY required challenge and the
 * set satisfies the step's {@code puzzleConfig} (count + allowed types). The
 * handler trusts NOTHING the client claims ("passed"/"verified" booleans), and
 * is FAIL-CLOSED on any missing/error/timeout/short-count/disallowed-type/
 * absent-metric condition — mirroring {@link FaceVerifyMfaStepHandler}.
 */
@DisplayName("PuzzleVerifyMfaStepHandler — server-authoritative re-score")
class PuzzleVerifyMfaStepHandlerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final UUID FLOW_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    private BiometricServicePort bio;
    private AuthFlowRepositoryPort authFlowRepository;
    private MfaSession session;
    private User user;
    private PuzzleVerifyMfaStepHandler handler;

    @BeforeEach
    void setUp() {
        bio = mock(BiometricServicePort.class);
        authFlowRepository = mock(AuthFlowRepositoryPort.class);
        session = mock(MfaSession.class);
        user = mock(User.class);
        lenient().when(user.getId()).thenReturn(USER_ID);
        lenient().when(session.getUserId()).thenReturn(USER_ID);
        lenient().when(session.getTenantId()).thenReturn(TENANT_ID);
        lenient().when(session.getFlowId()).thenReturn(FLOW_ID);
        lenient().when(session.getCurrentStep()).thenReturn(1);
        handler = new PuzzleVerifyMfaStepHandler(bio, authFlowRepository);
    }

    @Test
    @DisplayName("supports() → PUZZLE")
    void supportsPuzzle() {
        assertThat(handler.supports()).isEqualTo(AuthMethodType.PUZZLE);
    }

    // ---- helpers -----------------------------------------------------------

    /**
     * Stubs the current step's puzzleConfig: required challenge count + allowed
     * challenge types. Stored on the JSONB {@code config} blob exactly as the
     * auth-flow builder persists it (Phase 2.4 surfaces this same blob).
     */
    private void stubStepConfig(int count, String allowedTypesCsv) {
        String allowedJson = java.util.Arrays.stream(allowedTypesCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> "\"" + s + "\"")
                .collect(java.util.stream.Collectors.joining(","));
        String config = "{\"puzzleConfig\":{\"count\":" + count
                + ",\"allowedChallengeTypes\":[" + allowedJson + "]}}";
        AuthFlowStep step = mock(AuthFlowStep.class);
        lenient().when(step.getStepOrder()).thenReturn(1);
        lenient().when(step.getConfig()).thenReturn(config);
        AuthFlow flow = mock(AuthFlow.class);
        lenient().when(flow.getSteps()).thenReturn(List.of(step));
        lenient().when(authFlowRepository.findById(FLOW_ID)).thenReturn(Optional.of(flow));
    }

    /** A well-formed client challenge object with a non-empty metric. */
    private Map<String, Object> challenge(String action, Object metricValue) {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("value", metricValue);
        Map<String, Object> c = new HashMap<>();
        c.put("action", action);
        c.put("startTimestampMs", 1_000_000.0);
        c.put("endTimestampMs", 1_002_500.0);
        c.put("confidence", 0.92);
        c.put("metrics", metrics);
        return c;
    }

    private Map<String, Object> dataWith(List<Map<String, Object>> challenges) {
        Map<String, Object> data = new HashMap<>();
        data.put("challenges", challenges);
        return data;
    }

    /** Make bio return verified for the given action. */
    private void bioVerified(boolean verified) {
        when(bio.verifyPuzzleChallenge(anyMap())).thenAnswer(inv -> {
            Map<String, Object> req = inv.getArgument(0);
            Map<String, Object> resp = new HashMap<>();
            resp.put("verified", verified);
            resp.put("action", req.get("action"));
            return resp;
        });
    }

    // ---- happy path --------------------------------------------------------

    @Test
    @DisplayName("all challenges verified by bio AND config satisfied → success")
    void allVerified_configSatisfied_success() {
        stubStepConfig(2, "blink,smile");
        bioVerified(true);

        MfaStepResult result = handler.verify(session, user, dataWith(List.of(
                challenge("blink", 0.18),
                challenge("smile", 0.42))));

        assertThat(result.valid()).isTrue();
        // EVERY challenge was re-scored by the server (proves no client trust).
        verify(bio, atLeastOnce()).verifyPuzzleChallenge(anyMap());
    }

    // ---- the "no client trust" proof --------------------------------------

    @Test
    @DisplayName("client says passed:true but bio→verified:false → FAIL (no client trust)")
    void clientClaimsPassed_butBioRejects_fails() {
        stubStepConfig(1, "blink");
        bioVerified(false);

        Map<String, Object> forged = challenge("blink", 0.18);
        forged.put("passed", true);     // forged client claim
        forged.put("verified", true);   // forged client claim

        MfaStepResult result = handler.verify(session, user, dataWith(List.of(forged)));

        assertThat(result.valid()).isFalse();
        verify(bio, atLeastOnce()).verifyPuzzleChallenge(anyMap());
    }

    @Test
    @DisplayName("one challenge bio→verified:false → FAIL (every required challenge must verify)")
    void oneChallengeRejected_fails() {
        stubStepConfig(2, "blink,smile");
        when(bio.verifyPuzzleChallenge(anyMap())).thenAnswer(inv -> {
            Map<String, Object> req = inv.getArgument(0);
            Map<String, Object> resp = new HashMap<>();
            resp.put("verified", "smile".equals(req.get("action")) ? false : true);
            return resp;
        });

        MfaStepResult result = handler.verify(session, user, dataWith(List.of(
                challenge("blink", 0.18),
                challenge("smile", 0.42))));

        assertThat(result.valid()).isFalse();
    }

    // ---- hard-fail: bio response defects -----------------------------------

    @Test
    @DisplayName("bio response missing `verified` field → hard fail (fail-closed)")
    void missingVerifiedField_failsClosed() {
        stubStepConfig(1, "blink");
        when(bio.verifyPuzzleChallenge(anyMap())).thenReturn(Map.of("action", "blink"));

        MfaStepResult result = handler.verify(session, user,
                dataWith(List.of(challenge("blink", 0.18))));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio throws (error/timeout) → hard fail, no fail-open")
    void bioError_failsClosed() {
        stubStepConfig(1, "blink");
        when(bio.verifyPuzzleChallenge(anyMap()))
                .thenThrow(new RuntimeException("bio unreachable / timeout"));

        MfaStepResult result = handler.verify(session, user,
                dataWith(List.of(challenge("blink", 0.18))));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio soft-pass reason_code VALIDATION_UNAVAILABLE (404/5xx) → hard fail on AUTH path")
    void bioSoftPassUnavailable_failsClosedOnAuth() {
        stubStepConfig(1, "blink");
        // The adapter soft-passes (verified=true) with reason_code=VALIDATION_UNAVAILABLE
        // when bio is unreachable — fine for the TRAINING surface, a HOLE on the AUTH
        // path. The handler must reject it.
        when(bio.verifyPuzzleChallenge(anyMap())).thenReturn(Map.of(
                "verified", true,
                "action", "blink",
                "reason_code", "VALIDATION_UNAVAILABLE"));

        MfaStepResult result = handler.verify(session, user,
                dataWith(List.of(challenge("blink", 0.18))));

        assertThat(result.valid()).isFalse();
    }

    // ---- config enforcement (count + allowed types) ------------------------

    @Test
    @DisplayName("fewer challenges than puzzleConfig.count → fail, no bio call")
    void tooFewChallenges_fails() {
        stubStepConfig(2, "blink,smile");
        bioVerified(true);

        MfaStepResult result = handler.verify(session, user,
                dataWith(List.of(challenge("blink", 0.18))));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("a challenge type not in allowedChallengeTypes → fail, no bio call")
    void disallowedChallengeType_fails() {
        stubStepConfig(2, "blink,smile");
        bioVerified(true);

        MfaStepResult result = handler.verify(session, user, dataWith(List.of(
                challenge("blink", 0.18),
                challenge("turn_left", 25.0)))); // turn_left not allowed

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    // ---- auth-mode metric requirement --------------------------------------

    @Test
    @DisplayName("a challenge with ABSENT metrics → fail (auth requires the metric), no bio call")
    void absentMetric_failsOnAuth() {
        stubStepConfig(1, "blink");
        bioVerified(true);

        Map<String, Object> noMetric = challenge("blink", 0.18);
        noMetric.remove("metrics"); // bio would pass on structure alone — auth must not

        MfaStepResult result = handler.verify(session, user, dataWith(List.of(noMetric)));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("a challenge with EMPTY metrics map → fail (auth requires a real metric)")
    void emptyMetric_failsOnAuth() {
        stubStepConfig(1, "blink");
        bioVerified(true);

        Map<String, Object> emptyMetric = challenge("blink", 0.18);
        emptyMetric.put("metrics", new HashMap<>());

        MfaStepResult result = handler.verify(session, user, dataWith(List.of(emptyMetric)));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    // ---- malformed payloads ------------------------------------------------

    @Test
    @DisplayName("no challenges in payload → fail, no bio call")
    void noChallenges_fails() {
        stubStepConfig(1, "blink");

        MfaStepResult result = handler.verify(session, user, Map.of());

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("a challenge missing the action field → fail, no bio call")
    void missingAction_fails() {
        stubStepConfig(1, "blink");
        bioVerified(true);

        Map<String, Object> noAction = challenge("blink", 0.18);
        noAction.remove("action");

        MfaStepResult result = handler.verify(session, user, dataWith(List.of(noAction)));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("step config cannot be resolved (flow missing) → fail-closed, no bio call")
    void unresolvableConfig_failsClosed() {
        // No stubStepConfig() → authFlowRepository.findById returns empty.
        when(authFlowRepository.findById(FLOW_ID)).thenReturn(Optional.empty());
        bioVerified(true);

        MfaStepResult result = handler.verify(session, user,
                dataWith(List.of(challenge("blink", 0.18))));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("more challenges than count, all allowed + verified → success (count is a floor)")
    void moreThanCount_allAllowedAndVerified_success() {
        stubStepConfig(1, "blink,smile");
        bioVerified(true);

        List<Map<String, Object>> challenges = new ArrayList<>();
        challenges.add(challenge("blink", 0.18));
        challenges.add(challenge("smile", 0.42));

        MfaStepResult result = handler.verify(session, user, dataWith(challenges));

        assertThat(result.valid()).isTrue();
    }
}
