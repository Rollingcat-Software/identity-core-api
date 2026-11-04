package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.PuzzleSessionGuardPort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Server-authoritative VERDICT tests for {@link PuzzleVerifyMfaStepHandler}
 * (CV-2 of the puzzle-as-login convergence).
 *
 * <p>The crux: the client sends ONLY an opaque {@code puzzle_session_id}; the
 * handler asks the biometric-processor for the AUTHORITATIVE verdict (passing the
 * SERVER's user_id + tenant_id from the MFA session, never any client value) and
 * passes ONLY on {@code verified:true}. It is FAIL-CLOSED on a missing field,
 * a fail-closed adapter error map (404/non-2xx/transport), a {@code verified:false},
 * a missing server tenant, or any error/timeout — mirroring
 * {@link FaceVerifyMfaStepHandler}.
 */
@DisplayName("PuzzleVerifyMfaStepHandler — server-authoritative session verdict")
class PuzzleVerifyMfaStepHandlerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    private static final UUID TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    private static final UUID FLOW_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static final String SESSION_ID = "tok_opaque_server_issued_123";
    private static final int CURRENT_STEP = 1;

    private BiometricServicePort bio;
    private AuthFlowRepositoryPort authFlowRepository;
    private PuzzleSessionGuardPort guard;
    private MfaSession session;
    private User user;
    private PuzzleVerifyMfaStepHandler handler;

    @BeforeEach
    void setUp() {
        bio = mock(BiometricServicePort.class);
        authFlowRepository = mock(AuthFlowRepositoryPort.class);
        guard = mock(PuzzleSessionGuardPort.class);
        // Default: identity recorded at CREATE that bio advertised the legacy v1
        // contract (bio PUZZLE_TRACE_V2_ENABLED OFF), so every pre-v2 test below
        // asserts the unchanged flag-OFF behaviour. v2 tests override this.
        lenient().when(guard.traceContractFor(anyString()))
                .thenReturn(Optional.of(PuzzleSessionGuardPort.CONTRACT_V1));
        session = mock(MfaSession.class);
        user = mock(User.class);
        lenient().when(user.getId()).thenReturn(USER_ID);
        lenient().when(session.getUserId()).thenReturn(USER_ID);
        lenient().when(session.getTenantId()).thenReturn(TENANT_ID);
        lenient().when(session.getFlowId()).thenReturn(FLOW_ID);
        lenient().when(session.getCurrentStep()).thenReturn(CURRENT_STEP);
        // Default handler: SP-A client-side-embedding policy OFF (real policy, no
        // global enable, no canary), so the identity-binding branch never engages
        // unless a test rebuilds the handler with the policy ON. This keeps every
        // pre-SP-B (CV-2) test a pure liveness-only assertion. Mirrors
        // FaceVerifyMfaStepHandlerTest, which constructs a real policy too.
        handler = newHandler(false);
    }

    /**
     * Builds the handler with a REAL {@link ClientSideEmbeddingPolicy} whose
     * global master switch is {@code spaPolicyOn} (no per-tenant canary used in
     * these tests). Mirrors the construction style in
     * {@code FaceVerifyMfaStepHandlerTest}.
     */
    private PuzzleVerifyMfaStepHandler newHandler(boolean spaPolicyOn) {
        ClientSideEmbeddingPolicy policy = new ClientSideEmbeddingPolicy(spaPolicyOn, "");
        return new PuzzleVerifyMfaStepHandler(bio, authFlowRepository, policy, guard);
    }

    @Test
    @DisplayName("supports() → PUZZLE")
    void supportsPuzzle() {
        assertThat(handler.supports()).isEqualTo(AuthMethodType.PUZZLE);
    }

    // ---- helpers -----------------------------------------------------------

    private Map<String, Object> dataWithSessionId(Object sessionId) {
        Map<String, Object> data = new HashMap<>();
        data.put("puzzle_session_id", sessionId);
        return data;
    }

    private void bioVerdict(boolean verified) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("verified", verified);
        lenient().when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class))).thenReturn(resp);
        // Binding-required steps use the binding-carrying verdict (puzzle contract v2).
        lenient().when(bio.getPuzzleVerdictWithBinding(anyString(), any(UUID.class), any(UUID.class), any()))
                .thenReturn(resp);
    }

    // ---- SP-B identity-binding helpers --------------------------------------

    /**
     * Stubs the current flow step's persisted {@code config} JSONB so that
     * {@code puzzleConfig.alsoMatchFaceIdentity} reads as {@code bind}. Mirrors
     * the Task 2.4 round-trip blob shape.
     */
    private void stepBinding(boolean bind) {
        String configJson = "{\"puzzleConfig\":{\"allowedChallengeTypes\":[\"blink\",\"smile\"],"
                + "\"count\":2,\"difficulty\":\"standard\",\"alsoMatchFaceIdentity\":" + bind + "}}";
        AuthFlowStep step = mock(AuthFlowStep.class);
        lenient().when(step.getStepOrder()).thenReturn(CURRENT_STEP);
        lenient().when(step.getConfig()).thenReturn(configJson);
        AuthFlow flow = mock(AuthFlow.class);
        lenient().when(flow.getSteps()).thenReturn(List.of(step));
        lenient().when(authFlowRepository.findById(FLOW_ID)).thenReturn(Optional.of(flow));
    }

    /**
     * Rebuilds {@link #handler} with the SP-A client-side-embedding policy ON
     * (global master switch), so the identity-binding double-gate can engage.
     */
    private void embeddingPolicyOn() {
        handler = newHandler(true);
    }

    /** Stubs the bio embedding (identity) match verdict. */
    private void bioEmbeddingMatch(boolean verified) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("verified", verified);
        when(bio.verifyEmbedding(anyString(), any(UUID.class), any())).thenReturn(resp);
    }

    /** A valid 512-float embedding vector. */
    private static List<Double> embedding512() {
        List<Double> v = new ArrayList<>(512);
        for (int i = 0; i < 512; i++) {
            v.add(0.001 * i);
        }
        return v;
    }

    private Map<String, Object> dataWithSessionAndEmbedding(List<Double> embedding) {
        Map<String, Object> data = dataWithSessionId(SESSION_ID);
        data.put("embedding", embedding);
        return data;
    }

    // ---- happy path --------------------------------------------------------

    @Test
    @DisplayName("bio verdict verified:true → success")
    void verdictTrue_success() {
        bioVerdict(true);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isTrue();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
    }

    // ---- the "server-stamped identity" proof -------------------------------

    @Test
    @DisplayName("verdict uses the SERVER user_id/tenant_id, NOT any client-supplied identity")
    void verdictUsesServerIdentity_notClientValue() {
        bioVerdict(true);

        // Client tries to smuggle a foreign owner identity in the payload.
        Map<String, Object> data = dataWithSessionId(SESSION_ID);
        data.put("user_id", UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd").toString());
        data.put("tenant_id", UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").toString());

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();

        // The verdict MUST carry the SERVER MFA-session identity, never the client's.
        ArgumentCaptor<UUID> userCaptor = ArgumentCaptor.forClass(UUID.class);
        ArgumentCaptor<UUID> tenantCaptor = ArgumentCaptor.forClass(UUID.class);
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), userCaptor.capture(), tenantCaptor.capture());
        assertThat(userCaptor.getValue()).isEqualTo(USER_ID);
        assertThat(tenantCaptor.getValue()).isEqualTo(TENANT_ID);
    }

    @Test
    @DisplayName("client says passed/verified but bio→verified:false → FAIL (no client trust)")
    void clientClaimsPassed_butBioRejects_fails() {
        bioVerdict(false);

        Map<String, Object> data = dataWithSessionId(SESSION_ID);
        data.put("passed", true);   // forged client claim
        data.put("verified", true); // forged client claim

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isFalse();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
    }

    // ---- hard-fail: bio verdict defects ------------------------------------

    @Test
    @DisplayName("bio verdict verified:false → fail")
    void verdictFalse_fails() {
        bioVerdict(false);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio verdict missing `verified` field → hard fail (fail-closed)")
    void missingVerifiedField_failsClosed() {
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class)))
                .thenReturn(Map.of("foo", "bar"));

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("adapter fail-closed error map (404/non-2xx/transport: success=false, no `verified`) → hard fail")
    void adapterErrorMap_failsClosed() {
        // The adapter returns {success:false, message:...} (with NO `verified` key)
        // on a bio 404 (unknown/expired/consumed), other non-2xx, or transport error.
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class)))
                .thenReturn(Map.of("success", false, "message", "Puzzle session verdict rejected: 404"));

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio verdict null → hard fail")
    void nullVerdict_failsClosed() {
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class))).thenReturn(null);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("bio throws (error/timeout) → hard fail, no fail-open")
    void bioError_failsClosed() {
        when(bio.getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class)))
                .thenThrow(new RuntimeException("bio unreachable / timeout"));

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
    }

    // ---- malformed / missing payload ---------------------------------------

    @Test
    @DisplayName("no puzzle_session_id in payload → fail, no bio call")
    void noSessionId_fails() {
        MfaStepResult result = handler.verify(session, user, Map.of());

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("blank puzzle_session_id → fail, no bio call")
    void blankSessionId_fails() {
        MfaStepResult result = handler.verify(session, user, dataWithSessionId("   "));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    @Test
    @DisplayName("camelCase puzzleSessionId is also accepted → success")
    void camelCaseSessionId_accepted() {
        bioVerdict(true);
        Map<String, Object> data = new HashMap<>();
        data.put("puzzleSessionId", SESSION_ID);

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
    }

    @Test
    @DisplayName("MFA session carries no tenant → fail-closed, no bio call (cannot owner-bind)")
    void noServerTenant_failsClosed() {
        when(session.getTenantId()).thenReturn(null);

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
        verifyNoInteractions(bio);
    }

    // =====================================================================
    // SP-B Phase 5.2 — identity-binding branch (DOUBLE-gated, fail-closed).
    //
    // Binding REQUIRED = puzzleConfig.alsoMatchFaceIdentity==true AND the SP-A
    // ClientSideEmbeddingPolicy enabled for the tenant. When required, the SAME
    // step ALSO matches FACE identity via bio /verify-embedding on the
    // live-capture embedding. Pass-truth-table:
    //   liveness:true  + binding-off                     → PASS  (no verifyEmbedding)
    //   liveness:true  + binding-on + identity:true      → PASS
    //   liveness:true  + binding-on + identity:false/404 → FAIL
    //   liveness:true  + binding-on + no/short embedding → FAIL  (fail-closed)
    //   liveness:true  + config-on  + SP-A policy off    → PASS  (liveness-only)
    // Both bio calls carry the SERVER user_id/tenant_id, never any client value.
    // =====================================================================

    @Test
    @DisplayName("binding OFF (alsoMatchFaceIdentity=false): liveness verified → success, NO verifyEmbedding")
    void bindingOff_livenessOnly_success_noEmbeddingCall() {
        bioVerdict(true);
        stepBinding(false);
        embeddingPolicyOn(); // even with SP-A on, config flag off ⇒ binding NOT required

        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isTrue();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
        verify(bio, never()).verifyEmbedding(anyString(), any(UUID.class), any());
        // Gap Ü2: a liveness-only PUZZLE pins no embedding (it does not say whose face it was).
        verify(session, never()).setLivenessEmbeddingSha256(any());
    }

    @Test
    @DisplayName("binding ON (config true + SP-A policy on) + embedding present + both bio verified → success")
    void bindingOn_bothVerified_success() {
        bioVerdict(true);
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(embedding512()));

        assertThat(result.valid()).isTrue();
        verify(bio).getPuzzleVerdictWithBinding(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID), any());
        verify(bio).verifyEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), any());
        // Gap Ü2: the digest of EXACTLY the matched embedding is pinned on the MFA session.
        verify(session).setLivenessEmbeddingSha256(
                com.fivucsas.identity.application.service.mfa.LivenessEmbeddingDigest.sha256Hex(embedding512()));
    }

    @Test
    @DisplayName("binding ON + liveness verified but identity match FALSE → FAIL")
    void bindingOn_identityFalse_fails() {
        bioVerdict(true);
        bioEmbeddingMatch(false);
        stepBinding(true);
        embeddingPolicyOn();

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(embedding512()));

        assertThat(result.valid()).isFalse();
        verify(bio).verifyEmbedding(eq(TENANT_ID.toString()), eq(USER_ID), any());
        verify(session, never()).setLivenessEmbeddingSha256(any());
    }

    @Test
    @DisplayName("binding ON + identity match missing `verified` field → FAIL (fail-closed)")
    void bindingOn_identityMissingVerified_failsClosed() {
        bioVerdict(true);
        when(bio.verifyEmbedding(anyString(), any(UUID.class), any()))
                .thenReturn(Map.of("foo", "bar"));
        stepBinding(true);
        embeddingPolicyOn();

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(embedding512()));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("binding ON + identity match adapter error map (404: success=false, no `verified`) → FAIL")
    void bindingOn_identityAdapterErrorMap_failsClosed() {
        bioVerdict(true);
        when(bio.verifyEmbedding(anyString(), any(UUID.class), any()))
                .thenReturn(Map.of("success", false, "message", "Verification rejected: 404"));
        stepBinding(true);
        embeddingPolicyOn();

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(embedding512()));

        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("binding ON + liveness verified but NO embedding in data → FAIL (fail-closed, NOT liveness-only)")
    void bindingOn_noEmbedding_failsClosed() {
        bioVerdict(true);
        stepBinding(true);
        embeddingPolicyOn();

        // No `embedding` key at all → must NOT downgrade to a liveness-only pass.
        MfaStepResult result = handler.verify(session, user, dataWithSessionId(SESSION_ID));

        assertThat(result.valid()).isFalse();
        verify(bio, never()).verifyEmbedding(anyString(), any(UUID.class), any());
    }

    @Test
    @DisplayName("binding ON + wrong-length embedding (not 512) → FAIL (fail-closed)")
    void bindingOn_wrongLengthEmbedding_failsClosed() {
        bioVerdict(true);
        stepBinding(true);
        embeddingPolicyOn();

        List<Double> shortVec = new ArrayList<>();
        for (int i = 0; i < 128; i++) {
            shortVec.add(0.1);
        }

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(shortVec));

        assertThat(result.valid()).isFalse();
        verify(bio, never()).verifyEmbedding(anyString(), any(UUID.class), any());
    }

    @Test
    @DisplayName("config alsoMatchFaceIdentity=true but SP-A policy OFF → binding NOT required → liveness-only success")
    void configBindOn_butPolicyOff_livenessOnly_success() {
        bioVerdict(true);
        stepBinding(true);
        // SP-A policy stays OFF (default stub) → the double-gate keeps binding off.

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(embedding512()));

        assertThat(result.valid()).isTrue();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
        verify(bio, never()).verifyEmbedding(anyString(), any(UUID.class), any());
    }

    @Test
    @DisplayName("binding ON: BOTH bio calls carry the SERVER user_id/tenant_id, never a client value")
    void bindingOn_bothCallsUseServerIdentity() {
        bioVerdict(true);
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        // Client tries to smuggle a foreign owner identity in the payload.
        Map<String, Object> data = dataWithSessionAndEmbedding(embedding512());
        data.put("user_id", UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd").toString());
        data.put("tenant_id", UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee").toString());

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();

        // Liveness verdict — SERVER identity.
        verify(bio).getPuzzleVerdictWithBinding(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID), any());

        // Identity match — SERVER identity (tenant as the SERVER tenant string,
        // user as the SERVER user), NEVER the smuggled client values.
        ArgumentCaptor<String> tenantCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<UUID> userCaptor = ArgumentCaptor.forClass(UUID.class);
        verify(bio).verifyEmbedding(tenantCaptor.capture(), userCaptor.capture(), any());
        assertThat(tenantCaptor.getValue()).isEqualTo(TENANT_ID.toString());
        assertThat(userCaptor.getValue()).isEqualTo(USER_ID);
    }

    // =====================================================================
    // Puzzle contract v2 — binding-frame consistency check forwarding.
    // =====================================================================

    private static List<Integer> frameInts(int n) {
        List<Integer> f = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            f.add(1000 + i);
        }
        return f;
    }

    @Test
    @DisplayName("binding ON: the client binding_frame is sanitized to {t,f} and forwarded with the verdict")
    void bindingOn_forwardsSanitizedBindingFrame() {
        bioVerdict(true);
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        Map<String, Object> frame = new HashMap<>();
        frame.put("t", 123456);
        frame.put("f", frameInts(96));
        frame.put("evil", "ignored");
        Map<String, Object> data = dataWithSessionAndEmbedding(embedding512());
        data.put("binding_frame", frame);

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isTrue();
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(bio).getPuzzleVerdictWithBinding(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID), captor.capture());
        assertThat(captor.getValue()).containsOnlyKeys("t", "f");
        assertThat(captor.getValue()).containsEntry("t", 123456L);
        assertThat((List<?>) captor.getValue().get("f")).hasSize(96);
        verify(bio, never()).getPuzzleVerdict(anyString(), any(UUID.class), any(UUID.class));
    }

    /** A binding frame with the given tweaks applied to an otherwise-valid one. */
    private static Map<String, Object> frameWith(String key, Object value) {
        Map<String, Object> frame = new HashMap<>();
        frame.put("t", 123456);
        frame.put("f", frameInts(96));
        frame.put(key, value);
        return frame;
    }

    /**
     * S6: a malformed binding frame fails IN IDENTITY and the bio session is
     * CONSUMED (plain verdict) — never forwarded, never left live, no identity match.
     */
    private void assertMalformedFrameConsumesAndFails(Map<String, Object> frame) {
        bio = mock(BiometricServicePort.class);
        bioVerdict(true);
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();
        Map<String, Object> data = dataWithSessionAndEmbedding(embedding512());
        data.put("binding_frame", frame);

        MfaStepResult result = handler.verify(session, user, data);

        assertThat(result.valid()).isFalse();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
        verify(bio, never()).getPuzzleVerdictWithBinding(anyString(), any(UUID.class), any(UUID.class), any());
        verify(bio, never()).verifyEmbedding(anyString(), any(UUID.class), any());
    }

    @Test
    @DisplayName("S6: wrong-size binding frame (10 ints / a 63-int hand frame) → FAIL in identity, bio session consumed")
    void bindingOn_wrongSizeFrame_consumesAndFails() {
        assertMalformedFrameConsumesAndFails(frameWith("f", frameInts(10)));
        assertMalformedFrameConsumesAndFails(frameWith("f", frameInts(63)));
    }

    @Test
    @DisplayName("S6: binding-frame coordinate outside ±20000 → FAIL in identity, bio session consumed")
    void bindingOn_coordOutOfRange_consumesAndFails() {
        List<Integer> f = frameInts(96);
        f.set(5, 20_001);
        assertMalformedFrameConsumesAndFails(frameWith("f", f));
        List<Integer> g = frameInts(96);
        g.set(7, -20_001);
        assertMalformedFrameConsumesAndFails(frameWith("f", g));
    }

    @Test
    @DisplayName("S6: binding-frame t outside [0, 2^53] or non-integral → FAIL, bio session consumed")
    void bindingOn_badTimestamp_consumesAndFails() {
        assertMalformedFrameConsumesAndFails(frameWith("t", -1));
        assertMalformedFrameConsumesAndFails(frameWith("t", (1L << 53) + 1));
        assertMalformedFrameConsumesAndFails(frameWith("t", 12.5));
    }

    @Test
    @DisplayName("S6: binding-frame dims outside 64..8192 (when present) → FAIL, bio session consumed")
    void bindingOn_badFrameDims_consumesAndFails() {
        assertMalformedFrameConsumesAndFails(frameWith("frame_width", 32));
        assertMalformedFrameConsumesAndFails(frameWith("frame_height", 9000));
    }

    @Test
    @DisplayName("S6: bounds are inclusive — ±20000, t=0 and 2^53, dims 64/8192 are accepted (and dims not forwarded)")
    void extractBindingFrame_inclusiveBounds() {
        List<Integer> f = frameInts(96);
        f.set(0, 20_000);
        f.set(1, -20_000);
        Map<String, Object> frame = frameWith("f", f);
        frame.put("frame_width", 64);
        frame.put("frame_height", 8192);
        frame.put("t", 0);
        assertThat(PuzzleVerifyMfaStepHandler.extractBindingFrame(frame)).containsOnlyKeys("t", "f");
        frame.put("t", 1L << 53);
        assertThat(PuzzleVerifyMfaStepHandler.extractBindingFrame(frame)).isNotNull();
    }

    // =====================================================================
    // S5 — version handshake (binding_checked) on a v2 session.
    // =====================================================================

    private void v2Session() {
        lenient().when(guard.traceContractFor(SESSION_ID))
                .thenReturn(Optional.of(PuzzleSessionGuardPort.CONTRACT_V2));
    }

    private void bioBindingVerdict(Map<String, Object> resp) {
        when(bio.getPuzzleVerdictWithBinding(anyString(), any(UUID.class), any(UUID.class), any()))
                .thenReturn(resp);
    }

    private Map<String, Object> dataWithValidFrame() {
        Map<String, Object> data = dataWithSessionAndEmbedding(embedding512());
        data.put("binding_frame", frameWith("t", 123456));
        return data;
    }

    @Test
    @DisplayName("S5 v2: verified + binding_checked=true → success")
    void v2_bindingChecked_success() {
        v2Session();
        bioBindingVerdict(Map.of("verified", true, "binding_checked", true));
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        assertThat(handler.verify(session, user, dataWithValidFrame()).valid()).isTrue();
    }

    @Test
    @DisplayName("S5 v2: verified but NO binding_checked (bio ignored the binding) → FAIL, no identity match")
    void v2_verifiedWithoutBindingChecked_failsClosed() {
        v2Session();
        bioBindingVerdict(Map.of("verified", true));
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        assertThat(handler.verify(session, user, dataWithValidFrame()).valid()).isFalse();
        verify(bio, never()).verifyEmbedding(anyString(), any(UUID.class), any());
    }

    @Test
    @DisplayName("S5: contract UNKNOWN (no CREATE record) is treated strictly — no binding_checked → FAIL")
    void unknownContract_withoutBindingChecked_failsClosed() {
        when(guard.traceContractFor(SESSION_ID)).thenReturn(Optional.empty());
        bioBindingVerdict(Map.of("verified", true));
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        assertThat(handler.verify(session, user, dataWithValidFrame()).valid()).isFalse();
    }

    @Test
    @DisplayName("S5/S6 v2: binding required but NO binding_frame → FAIL in identity, bio session consumed")
    void v2_missingBindingFrame_consumesAndFails() {
        v2Session();
        bioVerdict(true);
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(embedding512()));

        assertThat(result.valid()).isFalse();
        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
        verify(bio, never()).getPuzzleVerdictWithBinding(anyString(), any(UUID.class), any(UUID.class), any());
    }

    @Test
    @DisplayName("S5 flag-OFF (CREATE recorded v1): binding_checked not required — legacy behaviour unchanged")
    void v1_bindingRequired_legacyPass() {
        bioVerdict(true); // {verified:true}, no binding_checked
        bioEmbeddingMatch(true);
        stepBinding(true);
        embeddingPolicyOn();

        assertThat(handler.verify(session, user, dataWithSessionAndEmbedding(embedding512())).valid()).isTrue();
        verify(bio).getPuzzleVerdictWithBinding(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID), isNull());
    }

    @Test
    @DisplayName("S5: binding NOT required → no contract lookup, plain verdict (flag-OFF no-binding unchanged)")
    void bindingOff_noContractLookup() {
        bioVerdict(true);
        stepBinding(false);

        assertThat(handler.verify(session, user, dataWithSessionId(SESSION_ID)).valid()).isTrue();
        verifyNoInteractions(guard);
    }

    @Test
    @DisplayName("binding ON: bio verdict false (e.g. v2 BINDING_OUTSIDE_WINDOW) → FAIL, no identity match")
    void bindingOn_bioBindingRejected_fails() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("verified", false);
        when(bio.getPuzzleVerdictWithBinding(anyString(), any(UUID.class), any(UUID.class), any()))
                .thenReturn(resp);
        stepBinding(true);
        embeddingPolicyOn();

        MfaStepResult result = handler.verify(session, user, dataWithSessionAndEmbedding(embedding512()));

        assertThat(result.valid()).isFalse();
        verify(bio, never()).verifyEmbedding(anyString(), any(UUID.class), any());
    }

    @Test
    @DisplayName("binding OFF: the binding_frame is never forwarded (plain verdict)")
    void bindingOff_doesNotForwardBindingFrame() {
        bioVerdict(true);
        stepBinding(false);
        embeddingPolicyOn();
        Map<String, Object> data = dataWithSessionId(SESSION_ID);
        data.put("binding_frame", Map.of("t", 1, "f", frameInts(96)));

        handler.verify(session, user, data);

        verify(bio).getPuzzleVerdict(eq(SESSION_ID), eq(USER_ID), eq(TENANT_ID));
        verify(bio, never()).getPuzzleVerdictWithBinding(anyString(), any(UUID.class), any(UUID.class), any());
    }
}
