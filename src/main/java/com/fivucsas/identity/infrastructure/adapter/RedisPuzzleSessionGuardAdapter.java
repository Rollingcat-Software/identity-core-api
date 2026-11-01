package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.PuzzleSessionGuardPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

/**
 * Redis implementation of {@link PuzzleSessionGuardPort}, following the same
 * INCR + EXPIRE-on-first pattern as {@code OtpService.acquireSendSlot}.
 * Unlike the OTP send throttle (fail-open), the create counter fails CLOSED:
 * the counter is the attempt cap itself, so an outage must not lift it.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RedisPuzzleSessionGuardAdapter implements PuzzleSessionGuardPort {

    static final String CREATES_PREFIX = "mfa:puzzle:creates:";
    static final String CONTRACT_PREFIX = "mfa:puzzle:contract:";

    private final StringRedisTemplate redisTemplate;

    @Override
    public long incrementCreates(String mfaSessionKey, Duration ttl) {
        String key = CREATES_PREFIX + mfaSessionKey;
        try {
            Long n = redisTemplate.opsForValue().increment(key);
            if (n == null) {
                throw new IllegalStateException("Redis returned no value for puzzle create counter");
            }
            if (n == 1L) {
                redisTemplate.expire(key, ttl);
            }
            return n;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            log.error("Redis unavailable for puzzle create counter: {}", e.getMessage());
            throw new IllegalStateException("Puzzle create counter unavailable", e);
        }
    }

    @Override
    public void recordTraceContract(String puzzleSessionId, String contract, Duration ttl) {
        try {
            redisTemplate.opsForValue().set(CONTRACT_PREFIX + puzzleSessionId, contract, ttl);
        } catch (Exception e) {
            // Best effort: an unrecorded contract is treated as "not v1" at the
            // verdict, i.e. the stricter binding_checked rule applies.
            log.warn("Could not record puzzle trace contract: {}", e.getMessage());
        }
    }

    @Override
    public Optional<String> traceContractFor(String puzzleSessionId) {
        try {
            return Optional.ofNullable(redisTemplate.opsForValue().get(CONTRACT_PREFIX + puzzleSessionId));
        } catch (Exception e) {
            log.warn("Could not read puzzle trace contract: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
