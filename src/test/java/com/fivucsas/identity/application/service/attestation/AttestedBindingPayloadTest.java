package com.fivucsas.identity.application.service.attestation;

import com.fivucsas.identity.application.port.output.AttestationChallengePort;
import com.fivucsas.identity.application.service.AttestedBindingPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@DisplayName("Attested puzzle binding — canonical payload, evidence parsing, challenge issue")
class AttestedBindingPayloadTest {

    /** Shared with client-apps AttestedBindingPayloadTest (and recomputed independently in Python). */
    static final String GOLDEN_SHA256 = "26b536124412eac9347ea789a73bda97a3406b7e5cddb55c2fbe5cfdf538e9f7";
    static final String GOLDEN_TRACE_DIGEST = "8843a760a10fd102f3cf6206ec69437632f5895072999f5cdba5c3230193364c";

    static byte[] golden() {
        byte[] nonce = new byte[32];
        for (int i = 0; i < 32; i++) {
            nonce[i] = (byte) i;
        }
        List<Long> coords = new ArrayList<>();
        for (int i = 0; i < 96; i++) {
            coords.add((long) (i * 3 - 100));
        }
        return AttestedBindingPayload.encode("puzzle-session-1", nonce,
                List.of(0.1, -0.25, 1.0 / 3, 0.0, -0.0, 1e-7),
                HexFormat.of().parseHex(GOLDEN_TRACE_DIGEST), 1234567L, coords);
    }

    @Test
    void goldenVector() throws Exception {
        byte[] p = golden();
        assertThat(p).hasSize(562);
        assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(p)))
                .isEqualTo(GOLDEN_SHA256);
    }

    @Test
    void rejectsBadDigestAndOutOfRangeCoordinate() {
        assertThatThrownBy(() -> AttestedBindingPayload.encode("s", new byte[32], List.of(1.0), new byte[31],
                0, List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AttestedBindingPayload.encode("s", new byte[32], List.of(1.0), new byte[32],
                0, List.of(1L << 40))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void signatureRoundTripAndTamper() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        byte[] payload = golden();
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(payload);
        byte[] sig = s.sign();
        assertThat(AttestedPuzzleBindingVerifier.verifySignature(kp.getPublic(), sig, payload)).isTrue();
        payload[100] ^= 1;
        assertThat(AttestedPuzzleBindingVerifier.verifySignature(kp.getPublic(), sig, payload)).isFalse();
        assertThat(AttestedPuzzleBindingVerifier.verifySignature(kp.getPublic(), new byte[]{1, 2}, payload)).isFalse();
        assertThat(AttestedPuzzleBindingVerifier.verifySignature(null, sig, payload)).isFalse();
    }

    @Test
    void evidenceParsing() {
        String cert = Base64.getEncoder().encodeToString(new byte[]{0x30, 0x00});
        String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{1, 2, 3});
        Map<String, Object> ok = Map.of("format", "android-key", "payload_version", 1,
                "certificate_chain", List.of(cert, cert), "signature", sig, "trace_digest", "ABCD");
        AttestedPuzzleBindingVerifier.Evidence e = AttestedPuzzleBindingVerifier.parseEvidence(ok);
        assertThat(e).isNotNull();
        assertThat(e.chain()).hasSize(2);
        assertThat(e.signature()).containsExactly(1, 2, 3);
        assertThat(e.clientTraceDigestHex()).isEqualTo("abcd");

        assertThat(AttestedPuzzleBindingVerifier.parseEvidence(null)).isNull();
        assertThat(AttestedPuzzleBindingVerifier.parseEvidence(Map.of("format", "apple-app-attest"))).isNull();
        assertThat(AttestedPuzzleBindingVerifier.parseEvidence(Map.of("format", "android-key", "payload_version", 2,
                "certificate_chain", List.of(cert), "signature", sig))).isNull();
        assertThat(AttestedPuzzleBindingVerifier.parseEvidence(Map.of("format", "android-key", "payload_version", 1,
                "certificate_chain", List.of(), "signature", sig))).isNull();
        assertThat(AttestedPuzzleBindingVerifier.parseEvidence(Map.of("format", "android-key", "payload_version", 1,
                "certificate_chain", List.of("%%%"), "signature", sig))).isNull();
        assertThat(AttestedPuzzleBindingVerifier.parseEvidence(Map.of("format", "android-key", "payload_version", 1,
                "certificate_chain", List.of(cert)))).isNull();
        List<String> tooLong = new ArrayList<>();
        for (int i = 0; i < 11; i++) {
            tooLong.add(cert);
        }
        assertThat(AttestedPuzzleBindingVerifier.parseEvidence(Map.of("format", "android-key", "payload_version", 1,
                "certificate_chain", tooLong, "signature", sig))).isNull();
    }

    @Test
    void traceDigestDecoding() {
        assertThat(AttestedPuzzleBindingVerifier.decodeTraceDigest(GOLDEN_TRACE_DIGEST)).hasSize(32);
        assertThat(AttestedPuzzleBindingVerifier.decodeTraceDigest(GOLDEN_TRACE_DIGEST.toUpperCase())).hasSize(32);
        assertThat(AttestedPuzzleBindingVerifier.decodeTraceDigest("zz".repeat(32))).isNull();
        assertThat(AttestedPuzzleBindingVerifier.decodeTraceDigest("ab")).isNull();
        assertThat(AttestedPuzzleBindingVerifier.decodeTraceDigest(null)).isNull();
    }

    @Test
    void challengeIssuerAndPolicy() {
        UUID tenant = UUID.randomUUID();
        AttestationChallengePort store = mock(AttestationChallengePort.class);
        AttestationChallengeIssuer off = new AttestationChallengeIssuer(new AttestedBindingPolicy(false, ""), store);
        assertThat(off.applies(tenant, true)).isFalse();
        AttestationChallengeIssuer canary = new AttestationChallengeIssuer(
                new AttestedBindingPolicy(false, " not-a-uuid , " + tenant.toString().toUpperCase()), store);
        assertThat(canary.applies(tenant, true)).isTrue();
        assertThat(canary.applies(tenant, false)).isFalse();
        assertThat(canary.applies(UUID.randomUUID(), true)).isFalse();
        assertThat(new AttestationChallengeIssuer(new AttestedBindingPolicy(true, ""), store).applies(null, true))
                .isTrue();

        UUID mfa = UUID.randomUUID();
        String nonce = canary.issue("ps-1", mfa);
        byte[] raw = Base64.getUrlDecoder().decode(nonce);
        assertThat(raw).hasSize(32);
        verify(store).store(eq("ps-1"), eq(mfa), eq(raw), eq(Duration.ofSeconds(300)));
        assertThat(canary.issue("ps-2", mfa)).isNotEqualTo(nonce);
        assertThatThrownBy(() -> canary.issue("ps-3", null)).isInstanceOf(IllegalStateException.class);
        verify(store, org.mockito.Mockito.times(2)).store(any(), any(), any(), any());
    }
}
