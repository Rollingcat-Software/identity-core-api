package com.fivucsas.identity.infrastructure.webauthn;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WebAuthnService} covering the P1-2/P1-3/P1-4 fixes:
 * <ul>
 *   <li>P1-2: origin must be in the explicit allowlist (no substring trick).</li>
 *   <li>P1-3: registration with null/empty clientDataJSON is a hard reject.</li>
 *   <li>P1-4: sign-counter regression is rejected; both-zero pair accepted with INFO.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("WebAuthnService Tests")
class WebAuthnServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOps;

    private WebAuthnService webAuthnService;

    private static final String RP_ID = "fivucsas.com";
    private static final List<String> ORIGINS = List.of(
            "https://app.fivucsas.com",
            "https://verify.fivucsas.com",
            "https://demo.fivucsas.com");

    @BeforeEach
    void setUp() {
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOps);
        webAuthnService = new WebAuthnService(redisTemplate, RP_ID, ORIGINS);
    }

    private static String b64UrlNoPad(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static String clientDataJsonB64(String type, String challenge, String origin) {
        String json = String.format("{\"type\":\"%s\",\"challenge\":\"%s\",\"origin\":\"%s\"}",
                type, challenge, origin);
        return b64UrlNoPad(json.getBytes(StandardCharsets.UTF_8));
    }

    @Nested
    @DisplayName("Registration challenge (P1-3 + P1-2 origin allowlist)")
    class RegistrationChallenge {

        @Test
        @DisplayName("rejects when clientDataJSON is null")
        void rejectsNullClientData() {
            UUID sessionId = UUID.randomUUID();
            when(valueOps.get(anyString())).thenReturn("storedChal");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, null);

            assertThat(ok).isFalse();
        }

        @Test
        @DisplayName("rejects when clientDataJSON is empty string")
        void rejectsEmptyClientData() {
            UUID sessionId = UUID.randomUUID();
            when(valueOps.get(anyString())).thenReturn("storedChal");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, "");

            assertThat(ok).isFalse();
        }

        @Test
        @DisplayName("accepts valid clientDataJSON with allowlisted origin")
        void acceptsValidClientData() {
            UUID sessionId = UUID.randomUUID();
            String challenge = "the-challenge";
            when(valueOps.get(anyString())).thenReturn(challenge);
            String cdj = clientDataJsonB64("webauthn.create", challenge, "https://app.fivucsas.com");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isTrue();
        }

        @Test
        @DisplayName("rejects substring-trick origin (attacker-fivucsas.com.evil.com)")
        void rejectsSubstringTrickOrigin() {
            UUID sessionId = UUID.randomUUID();
            String challenge = "the-challenge";
            when(valueOps.get(anyString())).thenReturn(challenge);
            String cdj = clientDataJsonB64("webauthn.create", challenge,
                    "https://attacker-fivucsas.com.evil.com");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isFalse();
        }

        @Test
        @DisplayName("rejects subdomain suffix attack (app.fivucsas.com.evil.com)")
        void rejectsSubdomainSuffixAttack() {
            UUID sessionId = UUID.randomUUID();
            String challenge = "the-challenge";
            when(valueOps.get(anyString())).thenReturn(challenge);
            String cdj = clientDataJsonB64("webauthn.create", challenge,
                    "https://app.fivucsas.com.evil.com");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isFalse();
        }

        @Test
        @DisplayName("rejects case-mismatched origin (RFC 6454 — case-sensitive)")
        void rejectsCaseMismatchedOrigin() {
            UUID sessionId = UUID.randomUUID();
            String challenge = "the-challenge";
            when(valueOps.get(anyString())).thenReturn(challenge);
            String cdj = clientDataJsonB64("webauthn.create", challenge,
                    "https://APP.fivucsas.com");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isFalse();
        }

        @Test
        @DisplayName("rejects type mismatch (webauthn.get on registration path)")
        void rejectsTypeMismatch() {
            UUID sessionId = UUID.randomUUID();
            String challenge = "the-challenge";
            when(valueOps.get(anyString())).thenReturn(challenge);
            String cdj = clientDataJsonB64("webauthn.get", challenge, "https://app.fivucsas.com");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isFalse();
        }

        @Test
        @DisplayName("rejects challenge mismatch")
        void rejectsChallengeMismatch() {
            UUID sessionId = UUID.randomUUID();
            when(valueOps.get(anyString())).thenReturn("expected-chal");
            String cdj = clientDataJsonB64("webauthn.create", "different-chal",
                    "https://app.fivucsas.com");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isFalse();
        }

        @Test
        @DisplayName("rejects when stored challenge has expired")
        void rejectsExpiredChallenge() {
            UUID sessionId = UUID.randomUUID();
            when(valueOps.get(anyString())).thenReturn(null);
            String cdj = clientDataJsonB64("webauthn.create", "x", "https://app.fivucsas.com");

            boolean ok = webAuthnService.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isFalse();
        }
    }

    @Nested
    @DisplayName("Sign counter validation (P1-4)")
    class SignCounter {

        @Test
        @DisplayName("monotonic increase is accepted")
        void monotonicIncreaseAccepted() {
            assertThat(webAuthnService.validateSignCount(5L, 4L)).isTrue();
            assertThat(webAuthnService.validateSignCount(1000L, 999L)).isTrue();
            assertThat(webAuthnService.validateSignCount(1L, 0L)).isTrue();
        }

        @Test
        @DisplayName("regression is rejected (clone detection)")
        void regressionRejected() {
            assertThat(webAuthnService.validateSignCount(4L, 5L)).isFalse();
            assertThat(webAuthnService.validateSignCount(0L, 5L)).isFalse();
            assertThat(webAuthnService.validateSignCount(5L, 5L)).isFalse(); // equal == cloned
        }

        @Test
        @DisplayName("both-zero pair is accepted (per spec note for non-counter authenticators)")
        void bothZeroAccepted() {
            assertThat(webAuthnService.validateSignCount(0L, 0L)).isTrue();
        }
    }

    @Nested
    @DisplayName("extractSignCount byte-level parsing")
    class ExtractSignCount {

        private String authDataWithCounter(long counter) {
            // 32-byte rpIdHash (zeros), 1-byte flags (zero), 4-byte big-endian counter
            byte[] data = new byte[37];
            data[33] = (byte) ((counter >>> 24) & 0xFF);
            data[34] = (byte) ((counter >>> 16) & 0xFF);
            data[35] = (byte) ((counter >>> 8) & 0xFF);
            data[36] = (byte) (counter & 0xFF);
            return b64UrlNoPad(data);
        }

        @Test
        @DisplayName("parses 4-byte big-endian counter")
        void parsesCounter() {
            assertThat(webAuthnService.extractSignCount(authDataWithCounter(0x00000001L))).isEqualTo(1L);
            assertThat(webAuthnService.extractSignCount(authDataWithCounter(0x12345678L))).isEqualTo(0x12345678L);
            assertThat(webAuthnService.extractSignCount(authDataWithCounter(0xFFFFFFFFL))).isEqualTo(0xFFFFFFFFL);
        }

        @Test
        @DisplayName("returns 0 when authData is too short")
        void returnsZeroOnShortData() {
            String shortData = b64UrlNoPad(new byte[10]);
            assertThat(webAuthnService.extractSignCount(shortData)).isEqualTo(0L);
        }
    }

    @Nested
    @DisplayName("User Verification flag (P1-4) — UV required on assertions")
    class UserVerificationFlag {

        /** 37-byte authData with the given flags byte at offset 32. */
        private String authDataWithFlags(int flags) {
            byte[] data = new byte[37];
            data[32] = (byte) (flags & 0xFF);
            return b64UrlNoPad(data);
        }

        @Test
        @DisplayName("UV bit (0x04) set -> flag detected")
        void uvSetDetected() {
            // UP|UV = 0x05
            assertThat(webAuthnService.isUserVerificationFlagSet(authDataWithFlags(0x05))).isTrue();
            // UV alone = 0x04
            assertThat(webAuthnService.isUserVerificationFlagSet(authDataWithFlags(0x04))).isTrue();
        }

        @Test
        @DisplayName("UP-only (0x01) -> UV flag NOT detected (rejected as not UV-strong)")
        void upOnlyHasNoUv() {
            assertThat(webAuthnService.isUserVerificationFlagSet(authDataWithFlags(0x01))).isFalse();
        }

        @Test
        @DisplayName("no flags set -> UV flag NOT detected")
        void noFlagsNoUv() {
            assertThat(webAuthnService.isUserVerificationFlagSet(authDataWithFlags(0x00))).isFalse();
        }

        @Test
        @DisplayName("null / short authData -> UV flag NOT detected (defensive)")
        void nullOrShortNoUv() {
            assertThat(webAuthnService.isUserVerificationFlagSet(null)).isFalse();
            assertThat(webAuthnService.isUserVerificationFlagSet("")).isFalse();
            assertThat(webAuthnService.isUserVerificationFlagSet(b64UrlNoPad(new byte[10]))).isFalse();
        }
    }

    @Nested
    @DisplayName("Empty allowlist disables WebAuthn (defensive default)")
    class EmptyAllowlist {

        @Test
        @DisplayName("any origin is rejected when allowlist is empty")
        void emptyAllowlistRejectsEverything() {
            WebAuthnService svc = new WebAuthnService(redisTemplate, RP_ID, List.of());

            UUID sessionId = UUID.randomUUID();
            String challenge = "x";
            when(valueOps.get(anyString())).thenReturn(challenge);
            String cdj = clientDataJsonB64("webauthn.create", challenge, "https://app.fivucsas.com");

            boolean ok = svc.validateRegistrationChallenge(sessionId, cdj);

            assertThat(ok).isFalse();
        }
    }
}
