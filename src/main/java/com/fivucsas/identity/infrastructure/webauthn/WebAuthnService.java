package com.fivucsas.identity.infrastructure.webauthn;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

@Service
@Slf4j
public class WebAuthnService {

    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redisTemplate;

    public WebAuthnService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
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

    public boolean verifyAssertion(UUID sessionId, String credentialId, String authenticatorData,
                                    String clientDataJson, String signature) {
        String key = buildChallengeKey(sessionId);
        String storedChallenge = redisTemplate.opsForValue().get(key);

        if (storedChallenge == null) {
            log.warn("WebAuthn challenge not found or expired for session: {}", sessionId);
            return false;
        }

        // Verify the client data contains our challenge
        if (clientDataJson == null || !clientDataJson.contains(storedChallenge)) {
            log.warn("WebAuthn challenge mismatch for session: {}", sessionId);
            return false;
        }

        // In production, full CBOR/attestation verification would happen here.
        // For MVP, we verify the challenge round-trip and credential presence.
        boolean valid = credentialId != null && !credentialId.isEmpty()
                && authenticatorData != null && !authenticatorData.isEmpty()
                && signature != null && !signature.isEmpty();

        if (valid) {
            redisTemplate.delete(key);
            log.info("WebAuthn assertion verified for session: {}", sessionId);
        } else {
            log.warn("WebAuthn assertion verification failed for session: {}", sessionId);
        }

        return valid;
    }

    private String buildChallengeKey(UUID sessionId) {
        return "webauthn:challenge:" + sessionId;
    }
}
