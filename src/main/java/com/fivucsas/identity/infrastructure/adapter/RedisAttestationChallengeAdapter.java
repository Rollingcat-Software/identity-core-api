package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AttestationChallengePort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Redis implementation of {@link AttestationChallengePort}. One key per bio puzzle
 * session ({@code mfa:puzzle:attest:<puzzleSessionId>}) holding
 * {@code <mfaSessionId>|<base64 nonce>}; consumed with GETDEL so a nonce can be
 * used at most once even under concurrent verify attempts.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RedisAttestationChallengeAdapter implements AttestationChallengePort {

    static final String PREFIX = "mfa:puzzle:attest:";

    private final StringRedisTemplate redisTemplate;

    @Override
    public void store(String puzzleSessionId, UUID mfaSessionId, byte[] nonce, Duration ttl) {
        String value = mfaSessionId + "|" + Base64.getEncoder().encodeToString(nonce);
        try {
            redisTemplate.opsForValue().set(PREFIX + puzzleSessionId, value, ttl);
        } catch (Exception e) {
            log.error("Redis unavailable for attestation challenge store: {}", e.getMessage());
            throw new IllegalStateException("Attestation challenge store unavailable", e);
        }
    }

    @Override
    public Optional<IssuedChallenge> consume(String puzzleSessionId) {
        String raw;
        try {
            raw = redisTemplate.opsForValue().getAndDelete(PREFIX + puzzleSessionId);
        } catch (Exception e) {
            log.warn("Could not consume attestation challenge: {}", e.getMessage());
            return Optional.empty();
        }
        if (raw == null) {
            return Optional.empty();
        }
        int sep = raw.indexOf('|');
        if (sep <= 0) {
            return Optional.empty();
        }
        try {
            return Optional.of(new IssuedChallenge(
                    UUID.fromString(raw.substring(0, sep)),
                    Base64.getDecoder().decode(raw.substring(sep + 1))));
        } catch (IllegalArgumentException e) {
            log.warn("Malformed attestation challenge record — treating as absent");
            return Optional.empty();
        }
    }
}
