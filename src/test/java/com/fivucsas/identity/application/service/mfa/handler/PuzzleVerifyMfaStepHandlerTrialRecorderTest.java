package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.PuzzleSessionGuardPort;
import com.fivucsas.identity.application.service.AttestedBindingPolicy;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.authorTrial.AuthorTrialRecorder;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The trial recorder hook on the REAL Puzzle handler: the handler must report the
 * liveness/identity decision to the recorder (observation only) without changing
 * its own result. Non-trial callers get the NO_OP recorder and are unaffected.
 */
@DisplayName("PuzzleVerifyMfaStepHandler — author-trial recorder hook")
class PuzzleVerifyMfaStepHandlerTrialRecorderTest {

    private static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final UUID FLOW_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final UUID MFA_SESSION_ID = UUID.fromString("12121212-3434-5656-7878-909090909090");
    private static final String SESSION_ID = "puzzle-session-trial";

    private BiometricServicePort bio;
    private AuthFlowRepositoryPort authFlowRepository;
    private PuzzleSessionGuardPort guard;
    private ClientSideEmbeddingPolicy policy;
    private AuthorTrialRecorder recorder;
    private MfaSession session;
    private User user;

    @BeforeEach
    void setUp() {
        bio = mock(BiometricServicePort.class);
        authFlowRepository = mock(AuthFlowRepositoryPort.class);
        guard = mock(PuzzleSessionGuardPort.class);
        policy = mock(ClientSideEmbeddingPolicy.class);
        recorder = mock(AuthorTrialRecorder.class);
        session = mock(MfaSession.class);
        user = mock(User.class);
        lenient().when(user.getId()).thenReturn(USER_ID);
        lenient().when(session.getId()).thenReturn(MFA_SESSION_ID);
        lenient().when(session.getUserId()).thenReturn(USER_ID);
        lenient().when(session.getTenantId()).thenReturn(TENANT_ID);
        lenient().when(session.getFlowId()).thenReturn(FLOW_ID);
        lenient().when(session.getCurrentStep()).thenReturn(1);
        lenient().when(guard.traceContractFor(anyString()))
                .thenReturn(Optional.of(PuzzleSessionGuardPort.CONTRACT_V1));
        lenient().when(policy.isEnabledForTenant(TENANT_ID)).thenReturn(true);
        stubFlow(true);
    }

    private PuzzleVerifyMfaStepHandler handler() {
        return new PuzzleVerifyMfaStepHandler(bio, authFlowRepository, policy, guard,
                new AttestedBindingPolicy(false, ""), null, null, recorder);
    }

    private void stubFlow(boolean binding) {
        AuthFlow flow = mock(AuthFlow.class);
        AuthFlowStep step = mock(AuthFlowStep.class);
        lenient().when(authFlowRepository.findById(FLOW_ID)).thenReturn(Optional.of(flow));
        lenient().when(flow.getSteps()).thenReturn(List.of(step));
        lenient().when(step.getStepOrder()).thenReturn(1);
        lenient().when(step.getConfig()).thenReturn("{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"blink\"],"
                + "\"count\":1,\"difficulty\":\"easy\",\"alsoMatchFaceIdentity\":" + binding + "}}");
    }

    private Map<String, Object> data(boolean withEmbedding) {
        Map<String, Object> data = new HashMap<>();
        data.put("puzzle_session_id", SESSION_ID);
        if (withEmbedding) {
            data.put("embedding", Collections.nCopies(512, 0.1));
        }
        return data;
    }

    private void verdict(boolean verified) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("verified", verified);
        lenient().when(bio.getPuzzleVerdict(anyString(), any(), any())).thenReturn(resp);
        lenient().when(bio.getPuzzleVerdictWithBinding(anyString(), any(), any(), any())).thenReturn(resp);
    }

    @Test
    void missingSessionId_RecordsTheFailure() {
        MfaStepResult result = handler().verify(session, user, new HashMap<>());

        org.assertj.core.api.Assertions.assertThat(result.valid()).isFalse();
        verify(recorder).stepFailed(MFA_SESSION_ID, TENANT_ID, null, null, "missing_puzzle_session_id");
    }

    @Test
    void livenessFailure_RecordsLivenessFailAndNoIdentityVerdict() {
        verdict(false);

        MfaStepResult result = handler().verify(session, user, data(false));

        org.assertj.core.api.Assertions.assertThat(result.valid()).isFalse();
        verify(recorder).stepFailed(MFA_SESSION_ID, TENANT_ID, "fail", null, "liveness_verdict_failed");
        verify(recorder, never()).stepPassed(any(), any(), org.mockito.ArgumentMatchers.anyBoolean(),
                any(), any(), any());
    }

    @Test
    void livenessOnlyPass_RecordsPassWithIdentityNa() {
        when(policy.isEnabledForTenant(TENANT_ID)).thenReturn(false);
        verdict(true);

        MfaStepResult result = handler().verify(session, user, data(false));

        org.assertj.core.api.Assertions.assertThat(result.valid()).isTrue();
        verify(recorder).stepPassed(MFA_SESSION_ID, TENANT_ID, false, null, null, null);
    }

    @Test
    void missingBindingFrameOnV2_RecordsNoLivenessVerdict() {
        // Pre-bio client failure: no PAD decision exists, so liveness must stay
        // blank (the export then excludes the technical row from the rates).
        when(guard.traceContractFor(SESSION_ID))
                .thenReturn(Optional.of(PuzzleSessionGuardPort.CONTRACT_V2));

        MfaStepResult result = handler().verify(session, user, data(true));

        org.assertj.core.api.Assertions.assertThat(result.valid()).isFalse();
        verify(recorder).stepFailed(MFA_SESSION_ID, TENANT_ID, null, "fail", "binding_frame_missing");
        verify(recorder, never()).stepPassed(any(), any(), org.mockito.ArgumentMatchers.anyBoolean(),
                any(), any(), any());
    }

    @Test
    void bindingPass_RecordsIdentityScoreFromBio() {
        verdict(true);
        Map<String, Object> match = new HashMap<>();
        match.put("verified", true);
        match.put("confidence", 0.71);
        match.put("distance", 0.29);
        match.put("threshold", 0.40);
        when(bio.verifyEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), any())).thenReturn(match);

        MfaStepResult result = handler().verify(session, user, data(true));

        org.assertj.core.api.Assertions.assertThat(result.valid()).isTrue();
        verify(recorder).stepPassed(MFA_SESSION_ID, TENANT_ID, true, 0.71, 0.29, 0.40);
    }

    @Test
    void bindingFailure_RecordsLivenessPassAndIdentityFail() {
        verdict(true);
        Map<String, Object> match = new HashMap<>();
        match.put("verified", false);
        match.put("confidence", 0.21);
        when(bio.verifyEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), any())).thenReturn(match);

        MfaStepResult result = handler().verify(session, user, data(true));

        org.assertj.core.api.Assertions.assertThat(result.valid()).isFalse();
        verify(recorder).stepFailed(MFA_SESSION_ID, TENANT_ID, "pass", "fail", "identity_match_failed");
        verify(recorder, never()).stepPassed(any(), any(), org.mockito.ArgumentMatchers.anyBoolean(),
                any(), any(), any());
    }
}