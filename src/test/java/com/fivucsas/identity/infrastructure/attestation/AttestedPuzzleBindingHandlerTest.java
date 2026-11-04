package com.fivucsas.identity.infrastructure.attestation;

import com.fivucsas.identity.application.port.output.AttestationChallengePort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.PuzzleSessionGuardPort;
import com.fivucsas.identity.application.service.AttestedBindingPolicy;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.attestation.AttestedBindingPayload;
import com.fivucsas.identity.application.service.attestation.AttestedPuzzleBindingVerifier;
import com.fivucsas.identity.application.service.mfa.handler.PuzzleVerifyMfaStepHandler;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * End-to-end attested puzzle binding through {@link PuzzleVerifyMfaStepHandler}
 * with the REAL {@link AndroidKeyAttestationVerifierAdapter} (synthetic chain under
 * a test root), the REAL canonical payload and ECDSA verification; only bio, Redis
 * and the flow repository are mocked.
 */
@DisplayName("Attested puzzle binding — handler end-to-end")
class AttestedPuzzleBindingHandlerTest {

    static final UUID USER_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
    static final UUID TENANT_ID = UUID.fromString("99999999-8888-7777-6666-555555555555");
    static final UUID FLOW_ID = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    static final UUID MFA_SESSION_ID = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000001");
    static final String PUZZLE_SESSION = "ps_opaque_1";
    static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");
    static final String TRACE_DIGEST = "8843a760a10fd102f3cf6206ec69437632f5895072999f5cdba5c3230193364c";

    BiometricServicePort bio;
    AttestationChallengePort challenges;
    PuzzleSessionGuardPort guard;
    MfaSession session;
    User user;
    byte[] nonce;
    TestAttestationChains.Chain chain;
    PuzzleVerifyMfaStepHandler handler;

    @BeforeEach
    void setUp() {
        bio = mock(BiometricServicePort.class);
        challenges = mock(AttestationChallengePort.class);
        guard = mock(PuzzleSessionGuardPort.class);
        lenient().when(guard.traceContractFor(anyString())).thenReturn(Optional.of(PuzzleSessionGuardPort.CONTRACT_V2));

        session = mock(MfaSession.class);
        lenient().when(session.getId()).thenReturn(MFA_SESSION_ID);
        lenient().when(session.getTenantId()).thenReturn(TENANT_ID);
        lenient().when(session.getFlowId()).thenReturn(FLOW_ID);
        lenient().when(session.getCurrentStep()).thenReturn(1);
        user = mock(User.class);
        lenient().when(user.getId()).thenReturn(USER_ID);

        nonce = new byte[32];
        new java.security.SecureRandom().nextBytes(nonce);
        TestAttestationChains.Kd kd = new TestAttestationChains.Kd();
        kd.challenge = nonce;
        chain = TestAttestationChains.chain(kd, NOW);
        lenient().when(challenges.consume(PUZZLE_SESSION))
                .thenReturn(Optional.of(new AttestationChallengePort.IssuedChallenge(MFA_SESSION_ID, nonce)));

        handler = handler(true);

        Map<String, Object> verdict = new HashMap<>();
        verdict.put("verified", true);
        verdict.put("binding_checked", true);
        verdict.put("trace_digest", TRACE_DIGEST);
        lenient().when(bio.getPuzzleVerdictWithAttestedBinding(anyString(), any(), any(), any())).thenReturn(verdict);
        lenient().when(bio.getPuzzleVerdictWithBinding(anyString(), any(), any(), any())).thenReturn(verdict);
        lenient().when(bio.verifyEmbedding(anyString(), any(), any())).thenReturn(Map.of("verified", true));
    }

    PuzzleVerifyMfaStepHandler handler(boolean attestedOn) {
        AndroidKeyAttestationVerifierAdapter adapter = new AndroidKeyAttestationVerifierAdapter(
                List.of(chain.rootCert()),
                new AndroidKeyAttestationVerifierAdapter.Settings(Set.of("com.fivucsas.mobile"),
                        Set.of("00".repeat(32)), false, true, true, true, false, Duration.ofMinutes(5)),
                new GoogleAttestationStatusList(() -> "{\"entries\":{}}", Duration.ofHours(1), Duration.ofHours(1),
                        Clock.fixed(NOW, ZoneOffset.UTC)),
                Clock.fixed(NOW, ZoneOffset.UTC));
        return new PuzzleVerifyMfaStepHandler(bio, flowsOf(),
                new ClientSideEmbeddingPolicy(true, ""), guard, new AttestedBindingPolicy(attestedOn, ""),
                challenges, new AttestedPuzzleBindingVerifier(adapter));
    }

    private AuthFlowRepositoryPort flowsCache;

    private AuthFlowRepositoryPort flowsOf() {
        if (flowsCache == null) {
            flowsCache = mock(AuthFlowRepositoryPort.class);
            AuthFlowStep step = mock(AuthFlowStep.class);
            when(step.getStepOrder()).thenReturn(1);
            when(step.getConfig()).thenReturn("{\"puzzleConfig\":{\"count\":2,\"alsoMatchFaceIdentity\":true}}");
            AuthFlow flow = mock(AuthFlow.class);
            when(flow.getSteps()).thenReturn(List.of(step));
            when(flowsCache.findById(FLOW_ID)).thenReturn(Optional.of(flow));
        }
        return flowsCache;
    }

    static List<Double> embedding(double seed) {
        List<Double> v = new ArrayList<>(512);
        for (int i = 0; i < 512; i++) {
            v.add(Math.sin(seed + i) / 23.0);
        }
        return v;
    }

    static List<Long> frameCoords() {
        List<Long> f = new ArrayList<>(96);
        for (int i = 0; i < 96; i++) {
            f.add((long) (i * 7 - 300));
        }
        return f;
    }

    String sign(PrivateKey key, List<Double> emb, String traceDigestHex) throws Exception {
        byte[] payload = AttestedBindingPayload.encode(PUZZLE_SESSION, nonce, emb,
                HexFormat.of().parseHex(traceDigestHex), 4321L, frameCoords());
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(key);
        s.update(payload);
        return Base64.getEncoder().encodeToString(s.sign());
    }

    Map<String, Object> data(List<Double> sentEmbedding, String signature, boolean withAttestation) {
        Map<String, Object> d = new HashMap<>();
        d.put("puzzle_session_id", PUZZLE_SESSION);
        d.put("embedding", sentEmbedding);
        Map<String, Object> frame = new LinkedHashMap<>();
        frame.put("t", 4321);
        frame.put("f", new ArrayList<>(frameCoords().stream().map(Long::intValue).toList()));
        d.put("binding_frame", frame);
        if (withAttestation) {
            List<String> certs = chain.der().stream().map(b -> Base64.getEncoder().encodeToString(b)).toList();
            Map<String, Object> att = new HashMap<>();
            att.put("format", "android-key");
            att.put("payload_version", 1);
            att.put("certificate_chain", certs);
            att.put("signature", signature);
            d.put("attestation", att);
        }
        return d;
    }

    @Test
    void validAttestedBindingPasses_andMatchesExactlyTheSignedEmbedding() throws Exception {
        List<Double> emb = embedding(1);
        assertThat(handler.verify(session, user, data(emb, sign(chain.leaf().getPrivate(), emb, TRACE_DIGEST), true))
                .valid()).isTrue();
        verify(bio).getPuzzleVerdictWithAttestedBinding(eq(PUZZLE_SESSION), eq(USER_ID), eq(TENANT_ID), any());
        verify(bio).verifyEmbedding(TENANT_ID.toString(), USER_ID, emb);
        verify(challenges).consume(PUZZLE_SESSION);
        // Gap Ü2: only the attested path pins the digest of EXACTLY the signed, matched embedding.
        verify(session).setLivenessEmbeddingSha256(
                com.fivucsas.identity.application.service.mfa.LivenessEmbeddingDigest.sha256Hex(emb));
    }

    @Test
    void splitCapture_victimEmbeddingSubstituted_fails() throws Exception {
        // The genuine app signed its own live embedding; an attacker swaps in a victim's.
        String sig = sign(chain.leaf().getPrivate(), embedding(1), TRACE_DIGEST);
        assertThat(handler.verify(session, user, data(embedding(2), sig, true)).valid()).isFalse();
        verify(bio, never()).verifyEmbedding(anyString(), any(), any());
        verify(session, never()).setLivenessEmbeddingSha256(any());
    }

    @Test
    void signatureOverDifferentTraceDigest_fails() throws Exception {
        List<Double> emb = embedding(1);
        String sig = sign(chain.leaf().getPrivate(), emb, "00".repeat(32));
        assertThat(handler.verify(session, user, data(emb, sig, true)).valid()).isFalse();
        verify(bio, never()).verifyEmbedding(anyString(), any(), any());
    }

    @Test
    void signatureByAnUnattestedKey_fails() throws Exception {
        List<Double> emb = embedding(1);
        String sig = sign(TestAttestationChains.ecKeyPair("secp256r1").getPrivate(), emb, TRACE_DIGEST);
        assertThat(handler.verify(session, user, data(emb, sig, true)).valid()).isFalse();
    }

    @Test
    void missingAttestation_failsClosed_andConsumesBioSession() throws Exception {
        assertThat(handler.verify(session, user, data(embedding(1), null, false)).valid()).isFalse();
        verify(bio).getPuzzleVerdict(PUZZLE_SESSION, USER_ID, TENANT_ID);
        verify(bio, never()).getPuzzleVerdictWithAttestedBinding(anyString(), any(), any(), any());
        verify(bio, never()).verifyEmbedding(anyString(), any(), any());
    }

    @Test
    void nonceNotIssuedOrAlreadyUsed_fails() throws Exception {
        when(challenges.consume(PUZZLE_SESSION)).thenReturn(Optional.empty());
        List<Double> emb = embedding(1);
        assertThat(handler.verify(session, user, data(emb, sign(chain.leaf().getPrivate(), emb, TRACE_DIGEST), true))
                .valid()).isFalse();
        verify(bio).getPuzzleVerdict(PUZZLE_SESSION, USER_ID, TENANT_ID);
    }

    @Test
    void nonceIssuedToAnotherMfaSession_fails() throws Exception {
        when(challenges.consume(PUZZLE_SESSION)).thenReturn(Optional.of(
                new AttestationChallengePort.IssuedChallenge(UUID.randomUUID(), nonce)));
        List<Double> emb = embedding(1);
        assertThat(handler.verify(session, user, data(emb, sign(chain.leaf().getPrivate(), emb, TRACE_DIGEST), true))
                .valid()).isFalse();
    }

    @Test
    void attestationFromAnEarlierSession_failsOnChallenge() throws Exception {
        byte[] fresh = new byte[32];
        fresh[0] = 9;
        when(challenges.consume(PUZZLE_SESSION)).thenReturn(Optional.of(
                new AttestationChallengePort.IssuedChallenge(MFA_SESSION_ID, fresh)));
        List<Double> emb = embedding(1);
        assertThat(handler.verify(session, user, data(emb, sign(chain.leaf().getPrivate(), emb, TRACE_DIGEST), true))
                .valid()).isFalse();
        verify(bio, never()).getPuzzleVerdictWithAttestedBinding(anyString(), any(), any(), any());
    }

    @Test
    void bioWithoutTraceDigest_failsClosed() throws Exception {
        when(bio.getPuzzleVerdictWithAttestedBinding(anyString(), any(), any(), any()))
                .thenReturn(Map.of("verified", true, "binding_checked", true));
        List<Double> emb = embedding(1);
        assertThat(handler.verify(session, user, data(emb, sign(chain.leaf().getPrivate(), emb, TRACE_DIGEST), true))
                .valid()).isFalse();
    }

    @Test
    void legacyV1Session_failsClosedWhenAttestationRequired() throws Exception {
        when(guard.traceContractFor(anyString())).thenReturn(Optional.of(PuzzleSessionGuardPort.CONTRACT_V1));
        List<Double> emb = embedding(1);
        assertThat(handler.verify(session, user, data(emb, sign(chain.leaf().getPrivate(), emb, TRACE_DIGEST), true))
                .valid()).isFalse();
    }

    @Test
    void policyOff_attestationIgnored_legacyBindingPath() {
        handler = handler(false);
        assertThat(handler.verify(session, user, data(embedding(1), null, false)).valid()).isTrue();
        verify(bio).getPuzzleVerdictWithBinding(eq(PUZZLE_SESSION), eq(USER_ID), eq(TENANT_ID), any());
        verify(challenges, never()).consume(anyString());
        // Gap Ü2: a non-attested binding pass does not make a later FACE embedding liveness-backed.
        verify(session, never()).setLivenessEmbeddingSha256(any());
    }
}
