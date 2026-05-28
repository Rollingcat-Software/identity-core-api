package com.fivucsas.identity.infrastructure.totp;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * S13 — used-code replay prevention tests for {@link TotpService}.
 *
 * <p>Drives the REAL service against a fake Redis whose {@code setIfAbsent}
 * faithfully reproduces {@code SET key 1 EX ttl NX} semantics, so we can prove:
 * a valid code is accepted exactly once, an immediate reuse of the SAME code is
 * rejected as a replay, and a code for a DIFFERENT time-step is still accepted.
 */
@ExtendWith(MockitoExtension.class)
class TotpServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;

    private TotpService service;

    /** Fake Redis key-set used to emulate NX (set-if-absent) atomicity. */
    private final Map<String, String> fakeRedis = new HashMap<>();

    private final DefaultCodeGenerator codeGenerator =
            new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
    private final SystemTimeProvider timeProvider = new SystemTimeProvider();

    @BeforeEach
    void setUp() {
        service = new TotpService(redisTemplate);
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        // Emulate SET key val EX ttl NX: returns true only if key was absent.
        lenient().when(valueOperations.setIfAbsent(anyString(), anyString(), any(Duration.class)))
                .thenAnswer(inv -> {
                    String key = inv.getArgument(0);
                    if (fakeRedis.containsKey(key)) {
                        return false; // already consumed = replay
                    }
                    fakeRedis.put(key, inv.getArgument(1));
                    return true;
                });
    }

    /** Generate the live TOTP code for a secret at the current time-step. */
    private String currentCode(String secret) throws Exception {
        long step = Math.floorDiv(timeProvider.getTime(), 30L);
        return codeGenerator.generate(secret, step);
    }

    private String codeForStep(String secret, long step) throws Exception {
        return codeGenerator.generate(secret, step);
    }

    @Test
    void verifyCodeForUser_acceptsValidCodeOnce_thenRejectsImmediateReplay() throws Exception {
        UUID userId = UUID.randomUUID();
        String secret = new DefaultSecretGenerator(32).generate();
        String code = currentCode(secret);

        // First use: valid + first time → accepted.
        assertThat(service.verifyCodeForUser(userId, secret, code)).isTrue();

        // Immediate reuse of the SAME code in the SAME window → rejected as replay.
        assertThat(service.verifyCodeForUser(userId, secret, code)).isFalse();
    }

    @Test
    void verifyCodeForUser_acceptsDifferentTimeStep_afterPreviousStepConsumed() throws Exception {
        UUID userId = UUID.randomUUID();
        String secret = new DefaultSecretGenerator(32).generate();

        long currentStep = Math.floorDiv(timeProvider.getTime(), 30L);
        // The +1 step is inside the acceptance window (allowedDiscrepancy=1)
        // but is a DIFFERENT code/time-step than the current one.
        String currentStepCode = codeForStep(secret, currentStep);
        String nextStepCode = codeForStep(secret, currentStep + 1);

        // Consume the current step.
        assertThat(service.verifyCodeForUser(userId, secret, currentStepCode)).isTrue();
        // Replaying the current-step code is rejected.
        assertThat(service.verifyCodeForUser(userId, secret, currentStepCode)).isFalse();

        // A code for the next (different) time-step is still accepted — only the
        // exact consumed (userId, timeStep) pair is blocked, not the whole user.
        if (!nextStepCode.equals(currentStepCode)) {
            assertThat(service.verifyCodeForUser(userId, secret, nextStepCode)).isTrue();
        }
    }

    @Test
    void verifyCodeForUser_perUserIsolation_sameCodeDifferentUsersBothAccepted() throws Exception {
        UUID userA = UUID.randomUUID();
        UUID userB = UUID.randomUUID();
        String secret = new DefaultSecretGenerator(32).generate();
        String code = currentCode(secret);

        // Same code, two different users — the consumed marker is keyed by user,
        // so both succeed (and each can be replayed only by being blocked per-user).
        assertThat(service.verifyCodeForUser(userA, secret, code)).isTrue();
        assertThat(service.verifyCodeForUser(userB, secret, code)).isTrue();
        // ...but each user's own replay is blocked.
        assertThat(service.verifyCodeForUser(userA, secret, code)).isFalse();
        assertThat(service.verifyCodeForUser(userB, secret, code)).isFalse();
    }

    @Test
    void verifyCodeForUser_rejectsInvalidCode_withoutConsumingAnything() throws Exception {
        UUID userId = UUID.randomUUID();
        String secret = new DefaultSecretGenerator(32).generate();

        // "000000" is overwhelmingly unlikely to be a valid code for a random secret.
        assertThat(service.verifyCodeForUser(userId, secret, "000000")).isFalse();
        // Nothing was marked consumed for an invalid code.
        assertThat(fakeRedis).isEmpty();
    }

    @Test
    void verifyCodeForUser_writesMarkerWithBoundedTtl() throws Exception {
        UUID userId = UUID.randomUUID();
        String secret = new DefaultSecretGenerator(32).generate();
        String code = currentCode(secret);

        // Capture the TTL passed to Redis to prove markers self-expire (bounded).
        when(valueOperations.setIfAbsent(anyString(), eq("1"), any(Duration.class)))
                .thenAnswer(inv -> {
                    Duration ttl = inv.getArgument(2);
                    // TTL must be short (covers the ~90s window with margin, <= 120s).
                    assertThat(ttl).isLessThanOrEqualTo(Duration.ofSeconds(120));
                    assertThat(ttl).isGreaterThanOrEqualTo(Duration.ofSeconds(90));
                    return true;
                });

        assertThat(service.verifyCodeForUser(userId, secret, code)).isTrue();
    }

    @Test
    void findMatchingTimeStep_returnsCurrentStep_forCurrentCode() throws Exception {
        String secret = new DefaultSecretGenerator(32).generate();
        long currentStep = Math.floorDiv(timeProvider.getTime(), 30L);
        String code = codeForStep(secret, currentStep);

        // Tolerate a 30s-boundary tick between our read and the service's:
        // the scan window is [-1, +1], so the matched step is within +/-1.
        assertThat(service.findMatchingTimeStep(secret, code))
                .isBetween(currentStep - 1, currentStep + 1);
    }

    @Test
    void findMatchingTimeStep_returnsMinusOne_forBogusCode() {
        String secret = new DefaultSecretGenerator(32).generate();
        assertThat(service.findMatchingTimeStep(secret, "000000")).isLessThan(0);
        assertThat(service.findMatchingTimeStep(secret, null)).isEqualTo(-1);
        assertThat(service.findMatchingTimeStep(null, "123456")).isEqualTo(-1);
    }
}
