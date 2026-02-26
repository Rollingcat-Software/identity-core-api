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

    public WebAuthnService(
            StringRedisTemplate redisTemplate,
            @Value("${webauthn.rp-id:fivucsas.rollingcatsoftware.com}") String rpId) {
        this.redisTemplate = redisTemplate;
        this.rpId = rpId;
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

        if (clientDataJsonB64 != null && !clientDataJsonB64.isEmpty()) {
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(clientDataJsonB64);
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
            } catch (Exception e) {
                log.warn("WebAuthn registration clientDataJSON parsing failed: {}", e.getMessage());
                return false;
            }
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
            byte[] keyBytes = Base64.getUrlDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pk = kf.generatePublic(keySpec);

            // Build signed data: authenticatorData || SHA-256(clientDataJSON)
            byte[] authData = Base64.getUrlDecoder().decode(authenticatorDataB64);
            byte[] clientDataJsonRaw = Base64.getUrlDecoder().decode(clientDataJsonB64);

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] clientDataHash = sha256.digest(clientDataJsonRaw);

            byte[] signedData = new byte[authData.length + clientDataHash.length];
            System.arraycopy(authData, 0, signedData, 0, authData.length);
            System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);

            // Verify signature
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pk);
            sig.update(signedData);

            byte[] signatureBytes = Base64.getUrlDecoder().decode(signatureB64);
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
            byte[] authData = Base64.getUrlDecoder().decode(authenticatorDataB64);
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
            byte[] decoded = Base64.getUrlDecoder().decode(clientDataJsonB64);
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

            // Verify origin contains expected RP ID
            String origin = clientData.has("origin") ? clientData.get("origin").asText() : null;
            if (origin == null || !origin.contains(rpId)) {
                log.warn("WebAuthn origin mismatch: expected origin containing '{}', got '{}'", rpId, origin);
                return false;
            }

            return true;
        } catch (Exception e) {
            log.warn("WebAuthn clientDataJSON parsing failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validates authenticatorData per WebAuthn spec:
     * - Must be at least 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
     * - RP ID hash must match expected RP ID
     * - User Present (UP) flag must be set
     */
    private boolean validateAuthenticatorData(String authenticatorDataB64) {
        if (authenticatorDataB64 == null || authenticatorDataB64.isEmpty()) {
            return false;
        }

        try {
            byte[] authData = Base64.getUrlDecoder().decode(authenticatorDataB64);

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
            boolean userPresent = (flags & 0x01) != 0;
            if (!userPresent) {
                log.warn("WebAuthn User Present flag not set");
                return false;
            }

            return true;
        } catch (Exception e) {
            log.warn("WebAuthn authenticatorData validation failed: {}", e.getMessage());
            return false;
        }
    }

    private String buildChallengeKey(UUID sessionId) {
        return "webauthn:challenge:" + sessionId;
    }
}
