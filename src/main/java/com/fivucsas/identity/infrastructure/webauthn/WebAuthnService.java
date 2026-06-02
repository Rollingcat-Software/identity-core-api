package com.fivucsas.identity.infrastructure.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@Slf4j
public class WebAuthnService {

    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final StringRedisTemplate redisTemplate;
    @Getter
    private final String rpId;
    /**
     * Explicit allowlist of accepted RP origins per WebAuthn §7.2 step 9.
     * Replaces the prior {@code origin.contains(rpId)} substring trick that
     * accepted phishing hosts like {@code https://attacker-fivucsas.com.evil.com}.
     * Comparison is exact-match and case-sensitive (RFC 6454 §4).
     */
    private final Set<String> allowedOrigins;

    public WebAuthnService(
            StringRedisTemplate redisTemplate,
            @Value("${webauthn.rp-id:fivucsas.com}") String rpId,
            @Value("${app.webauthn.allowed-origins:}") List<String> allowedOrigins) {
        this.redisTemplate = redisTemplate;
        this.rpId = rpId;
        this.allowedOrigins = allowedOrigins == null ? Set.of() : Set.copyOf(allowedOrigins);
        if (this.allowedOrigins.isEmpty()) {
            log.warn("WebAuthn: app.webauthn.allowed-origins is empty — every assertion will be rejected. " +
                    "Configure the property to enable WebAuthn authentication.");
        } else {
            log.info("WebAuthn: configured with {} allowed origin(s): {}",
                    this.allowedOrigins.size(), this.allowedOrigins);
        }
    }

    public String generateChallenge(UUID sessionId) {
        byte[] challengeBytes = new byte[32];
        RANDOM.nextBytes(challengeBytes);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

        String key = buildChallengeKey(sessionId);
        redisTemplate.opsForValue().set(key, challenge, CHALLENGE_TTL);
        log.debug("WebAuthn challenge generated for session: {}", sessionId);
        return challenge;
    }

    /**
     * Validates a registration challenge by checking that the clientDataJSON
     * contains the expected challenge and type "webauthn.create".
     */
    public boolean validateRegistrationChallenge(UUID sessionId, String clientDataJsonB64) {
        String key = buildChallengeKey(sessionId);
        String storedChallenge = redisTemplate.opsForValue().get(key);

        if (storedChallenge == null) {
            log.warn("WebAuthn registration challenge not found or expired for session: {}", sessionId);
            return false;
        }

        // P1-3: clientDataJSON is REQUIRED. Previously a null/empty value silently
        // skipped the entire challenge proof, allowing any registration to succeed
        // (and consume the Redis challenge) without ever proving freshness.
        if (clientDataJsonB64 == null || clientDataJsonB64.isEmpty()) {
            log.warn("WebAuthn: clientDataJSON missing — rejecting registration for session: {}", sessionId);
            return false;
        }

        try {
            byte[] decoded = decodeBase64(clientDataJsonB64);
            JsonNode clientData = OBJECT_MAPPER.readTree(decoded);

            String type = clientData.has("type") ? clientData.get("type").asText() : null;
            if (!"webauthn.create".equals(type)) {
                log.warn("WebAuthn clientData type mismatch: expected 'webauthn.create', got '{}'", type);
                return false;
            }

            String challenge = clientData.has("challenge") ? clientData.get("challenge").asText() : null;
            if (!storedChallenge.equals(challenge)) {
                log.warn("WebAuthn challenge mismatch in registration clientDataJSON");
                return false;
            }

            // P1-2: origin must be in the explicit allowlist (exact-match, case-sensitive).
            String origin = clientData.has("origin") ? clientData.get("origin").asText() : null;
            if (!isOriginAllowed(origin)) {
                log.warn("WebAuthn registration origin not in allowlist: '{}'", origin);
                return false;
            }
        } catch (Exception e) {
            log.warn("WebAuthn registration clientDataJSON parsing failed: {}", e.getMessage());
            return false;
        }

        // Consume the challenge
        redisTemplate.delete(key);
        return true;
    }

    /**
     * Verifies a WebAuthn authentication assertion with full cryptographic signature verification.
     *
     * @param sessionId the auth session ID
     * @param credentialId the credential ID from the authenticator
     * @param authenticatorData base64url-encoded authenticator data
     * @param clientDataJson base64url-encoded client data JSON
     * @param signature base64url-encoded signature
     * @param publicKeyBase64 base64url-encoded X.509 public key for verification
     * @return true if assertion is valid
     */
    public boolean verifyAssertion(UUID sessionId, String credentialId, String authenticatorData,
                                    String clientDataJson, String signature, String publicKeyBase64) {
        String key = buildChallengeKey(sessionId);
        String storedChallenge = redisTemplate.opsForValue().get(key);

        if (storedChallenge == null) {
            log.warn("WebAuthn challenge not found or expired for session: {}", sessionId);
            return false;
        }

        // Step 1: Validate clientDataJSON structure and challenge
        if (!validateClientData(clientDataJson, storedChallenge)) {
            log.warn("WebAuthn clientDataJSON validation failed for session: {}", sessionId);
            return false;
        }

        // Step 2: Validate authenticatorData structure
        if (!validateAuthenticatorData(authenticatorData)) {
            log.warn("WebAuthn authenticatorData validation failed for session: {}", sessionId);
            return false;
        }

        // Step 3: Validate credential ID and signature are present
        if (credentialId == null || credentialId.isEmpty()) {
            log.warn("WebAuthn missing credentialId for session: {}", sessionId);
            return false;
        }
        if (signature == null || signature.isEmpty()) {
            log.warn("WebAuthn missing signature for session: {}", sessionId);
            return false;
        }

        // Step 4: Verify cryptographic signature
        if (publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
            log.warn("WebAuthn: no public key available for credential: {} session: {}", credentialId, sessionId);
            return false;
        }

        boolean sigValid = verifyCryptographicSignature(
                publicKeyBase64, authenticatorData, clientDataJson, signature);
        if (!sigValid) {
            log.warn("WebAuthn cryptographic signature verification failed for session: {}", sessionId);
            return false;
        }

        // Consume the challenge (one-time use)
        redisTemplate.delete(key);
        log.info("WebAuthn assertion fully verified for session: {}", sessionId);
        return true;
    }

    /**
     * Verifies the ECDSA signature over authenticatorData || SHA-256(clientDataJSON).
     */
    private boolean verifyCryptographicSignature(String publicKeyBase64, String authenticatorDataB64,
                                                  String clientDataJsonB64, String signatureB64) {
        try {
            // Decode the public key
            byte[] keyBytes = decodeBase64(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pk = kf.generatePublic(keySpec);

            // Build signed data: authenticatorData || SHA-256(clientDataJSON)
            byte[] authData = decodeBase64(authenticatorDataB64);
            byte[] clientDataJsonRaw = decodeBase64(clientDataJsonB64);

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] clientDataHash = sha256.digest(clientDataJsonRaw);

            byte[] signedData = new byte[authData.length + clientDataHash.length];
            System.arraycopy(authData, 0, signedData, 0, authData.length);
            System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);

            // Verify signature
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pk);
            sig.update(signedData);

            byte[] signatureBytes = decodeBase64(signatureB64);
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            log.warn("WebAuthn ECDSA signature verification error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts the sign count from authenticator data (bytes 33-36, big-endian).
     */
    public long extractSignCount(String authenticatorDataB64) {
        try {
            byte[] authData = decodeBase64(authenticatorDataB64);
            if (authData.length < 37) return 0;
            return ((authData[33] & 0xFFL) << 24) |
                   ((authData[34] & 0xFFL) << 16) |
                   ((authData[35] & 0xFFL) << 8) |
                   (authData[36] & 0xFFL);
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Validates the WebAuthn sign-counter per spec §6.1 step 17.
     *
     * <ul>
     *   <li>If both new and stored are 0, accept with INFO log — some authenticators
     *       (especially platform authenticators on Apple/Android) deliberately
     *       always emit 0 for privacy reasons; the spec permits this.</li>
     *   <li>Otherwise, require {@code newCount &gt; storedCount}. Equal or lesser
     *       values indicate a cloned authenticator and MUST be rejected.</li>
     * </ul>
     *
     * @return {@code true} if the counter is acceptable, {@code false} if it
     *         indicates a possible cloned credential.
     */
    public boolean validateSignCount(long newCount, long storedCount) {
        if (newCount == 0 && storedCount == 0) {
            log.info("WebAuthn sign-counter both zero — accepting per spec note (authenticator does not implement counter)");
            return true;
        }
        if (newCount > storedCount) {
            return true;
        }
        log.warn("WebAuthn sign-counter regression — possible cloned credential. new={}, stored={}",
                newCount, storedCount);
        return false;
    }

    /**
     * Returns {@code true} when {@code origin} is non-null and exactly matches
     * one of the configured {@code app.webauthn.allowed-origins} entries.
     * Comparison is case-sensitive (RFC 6454 §4).
     */
    private boolean isOriginAllowed(String origin) {
        if (origin == null || origin.isEmpty()) {
            return false;
        }
        return allowedOrigins.contains(origin);
    }

    /**
     * Validates clientDataJSON per WebAuthn spec:
     * - Must be valid JSON
     * - type must be "webauthn.get"
     * - challenge must match the stored challenge
     * - origin must match the expected RP origin
     */
    private boolean validateClientData(String clientDataJsonB64, String storedChallenge) {
        if (clientDataJsonB64 == null || clientDataJsonB64.isEmpty()) {
            return false;
        }

        try {
            byte[] decoded = decodeBase64(clientDataJsonB64);
            JsonNode clientData = OBJECT_MAPPER.readTree(decoded);

            // Verify type
            String type = clientData.has("type") ? clientData.get("type").asText() : null;
            if (!"webauthn.get".equals(type)) {
                log.warn("WebAuthn clientData type mismatch: expected 'webauthn.get', got '{}'", type);
                return false;
            }

            // Verify challenge
            String challenge = clientData.has("challenge") ? clientData.get("challenge").asText() : null;
            if (!storedChallenge.equals(challenge)) {
                log.warn("WebAuthn challenge mismatch in clientDataJSON");
                return false;
            }

            // P1-2: origin must be in the explicit allowlist (exact-match, case-sensitive
            // per RFC 6454 §4). Replaces the previous substring check that accepted
            // phishing hosts whose hostname contained the rpId as a substring.
            String origin = clientData.has("origin") ? clientData.get("origin").asText() : null;
            if (!isOriginAllowed(origin)) {
                log.warn("WebAuthn assertion origin not in allowlist: '{}'", origin);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.warn("WebAuthn clientDataJSON parsing failed: {}", e.getMessage());
            return false;
        }
    }

    /** authenticatorData flags byte (offset 32): User Present. */
    static final int FLAG_USER_PRESENT = 0x01;
    /** authenticatorData flags byte (offset 32): User Verified. */
    static final int FLAG_USER_VERIFIED = 0x04;

    /**
     * Validates authenticatorData per WebAuthn spec:
     * - Must be at least 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
     * - RP ID hash must match expected RP ID
     * - User Present (UP, 0x01) flag must be set
     * - User Verified (UV, 0x04) flag must be set (P1-4, 2026-06-02)
     *
     * <p>P1-4: previously only UP was checked, so a UP-only assertion (mere
     * presence — a touch with NO biometric/PIN user-verification) was accepted
     * as if it were UV-strong. For a login factor we require UV. Registration
     * for the discoverable-passkey path already sets
     * {@code userVerification="required"} (DeviceController passkey
     * register-options), so passkeys created there carry UV. NOTE: the legacy
     * platform/fingerprint register-options + the non-passkey authenticate-
     * options request {@code userVerification="preferred"} — an authenticator
     * that returns a UP-only assertion under "preferred" will now FAIL here.
     * See the PR description for the rollout/rollback note.
     */
    private boolean validateAuthenticatorData(String authenticatorDataB64) {
        if (authenticatorDataB64 == null || authenticatorDataB64.isEmpty()) {
            return false;
        }

        try {
            byte[] authData = decodeBase64(authenticatorDataB64);

            // Minimum length: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37
            if (authData.length < 37) {
                log.warn("WebAuthn authenticatorData too short: {} bytes", authData.length);
                return false;
            }

            // Verify RP ID hash (first 32 bytes)
            byte[] rpIdHash = new byte[32];
            System.arraycopy(authData, 0, rpIdHash, 0, 32);

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] expectedRpIdHash = sha256.digest(rpId.getBytes(StandardCharsets.UTF_8));

            if (!MessageDigest.isEqual(rpIdHash, expectedRpIdHash)) {
                log.warn("WebAuthn RP ID hash mismatch");
                return false;
            }

            // Verify flags (byte 32)
            byte flags = authData[32];
            boolean userPresent = (flags & FLAG_USER_PRESENT) != 0;
            if (!userPresent) {
                log.warn("WebAuthn User Present flag not set");
                return false;
            }

            // P1-4: require User Verification on assertions. A UP-only assertion
            // (presence without biometric/PIN) must not satisfy a login factor.
            boolean userVerified = (flags & FLAG_USER_VERIFIED) != 0;
            if (!userVerified) {
                log.warn("WebAuthn User Verified flag not set (UP-only assertion rejected)");
                return false;
            }

            return true;
        } catch (Exception e) {
            log.warn("WebAuthn authenticatorData validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Visible-for-test: is the User Verified (UV, 0x04) flag set in the flags
     * byte (offset 32) of the given base64 authenticatorData? Returns false
     * when the data is null/short/undecodable. Mirrors the byte-level parsing
     * style of {@link #extractSignCount(String)}.
     */
    boolean isUserVerificationFlagSet(String authenticatorDataB64) {
        if (authenticatorDataB64 == null || authenticatorDataB64.isEmpty()) {
            return false;
        }
        try {
            byte[] authData = decodeBase64(authenticatorDataB64);
            if (authData.length < 33) {
                return false;
            }
            return (authData[32] & FLAG_USER_VERIFIED) != 0;
        } catch (Exception e) {
            return false;
        }
    }

    private String buildChallengeKey(UUID sessionId) {
        return "webauthn:challenge:" + sessionId;
    }

    /**
     * Decodes a base64 string that may be standard (+ /) or URL-safe (- _) encoded.
     * The frontend uses btoa() which produces standard base64, while the WebAuthn spec
     * often uses base64url. This helper normalizes both to work correctly.
     */
    private byte[] decodeBase64(String input) {
        // Convert standard base64 chars to URL-safe before decoding
        String normalized = input.replace('+', '-').replace('/', '_');
        // Remove any padding — URL decoder handles unpadded
        normalized = normalized.replaceAll("=+$", "");
        return Base64.getUrlDecoder().decode(normalized);
    }
}
