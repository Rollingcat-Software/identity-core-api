package com.fivucsas.identity.infrastructure.stepup;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

@Service
@Slf4j
public class StepUpChallengeService {

    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final long CHALLENGE_TTL_SECONDS = CHALLENGE_TTL.toSeconds();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redisTemplate;

    public StepUpChallengeService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String generateChallenge(UUID userId, String deviceFingerprint) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redisTemplate.opsForValue().set(buildKey(userId, deviceFingerprint), challenge, CHALLENGE_TTL);
        log.debug("Step-up challenge generated for user={}, device={}", userId, deviceFingerprint);
        return challenge;
    }

    public long getChallengeExpiresInSeconds() {
        return CHALLENGE_TTL_SECONDS;
    }

    public String consumeChallenge(UUID userId, String deviceFingerprint) {
        String key = buildKey(userId, deviceFingerprint);
        String challenge = redisTemplate.opsForValue().get(key);
        if (challenge != null) {
            redisTemplate.delete(key);
        }
        return challenge;
    }

    public boolean verifySignature(String publicKeyBase64, String challengeBase64, String signatureBase64) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pk = kf.generatePublic(keySpec);

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pk);
            sig.update(Base64.getUrlDecoder().decode(challengeBase64));
            return sig.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (Exception e) {
            log.warn("ECDSA signature verification failed: {}", e.getMessage());
            return false;
        }
    }

    private String buildKey(UUID userId, String deviceFingerprint) {
        return "stepup:challenge:" + userId + ":" + deviceFingerprint;
    }
}
