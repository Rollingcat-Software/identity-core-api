package com.fivucsas.identity.infrastructure.totp;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TOTP (RFC 6238) generation and verification.
 *
 * <p><strong>S13 — used-code replay prevention.</strong> A TOTP code is only
 * valid for its 30-second time-step (plus or minus one step for clock drift,
 * giving roughly a 90-second acceptance window). An attacker who observes a
 * code (shoulder-surf, phishing relay, leaked log) could otherwise replay the
 * SAME code a second time while it is still inside that window. To stop this we
 * record the exact time-step a code was consumed against and reject a second
 * use of the same {@code (userId, timeStep)} pair.
 *
 * <p><strong>This is NOT an infinite blacklist.</strong> Each consumed marker
 * is written with a short TTL ({@link #CONSUMED_TTL}, ~120s) so it
 * <em>self-expires</em> the moment the code it guards can no longer possibly be
 * accepted by the verifier. Only a tiny, bounded number of markers (at most the
 * 3 in-window time-steps) can exist per user at any instant; everything older
 * is gone. Storage never grows unbounded.
 *
 * <p><strong>Storage:</strong> Redis ({@link StringRedisTemplate}, already wired
 * app-wide via {@code RedisMessagingConfig}) using {@code SET key 1 EX ttl NX}
 * semantics ({@link org.springframework.data.redis.core.ValueOperations#setIfAbsent}).
 * This is atomic and multi-instance correct — two concurrent verifies of the
 * same code on different API instances cannot both succeed. If Redis is
 * unavailable we fall back to a bounded in-memory TTL map (lazy eviction),
 * mirroring {@code AntiReplayFilter}.
 */
@Service
@Slf4j
public class TotpService {

    private static final int SECRET_LENGTH = 32;
    private static final int TIME_PERIOD_SECONDS = 30;
    /** Clock-drift tolerance in time-steps, matching the verifier's default (+/-1). */
    private static final int ALLOWED_DISCREPANCY = 1;
    /**
     * TTL for a consumed-step marker. Must cover the full acceptance window
     * (current step plus the +/-1 drift steps) with margin. The widest a code
     * can be accepted is ~90s; 120s gives a safety margin while still letting
     * every marker self-expire shortly after the code dies.
     */
    private static final Duration CONSUMED_TTL = Duration.ofSeconds(120);
    private static final String CONSUMED_KEY_PREFIX = "totp:used:";

    // Bounded in-memory fallback (used only when Redis is unavailable).
    private static final int MAX_FALLBACK_ENTRIES = 50_000;
    private final ConcurrentHashMap<String, Long> fallbackConsumed = new ConcurrentHashMap<>();
    private final AtomicLong lastFallbackCleanup = new AtomicLong(System.currentTimeMillis());

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(SECRET_LENGTH);
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier =
            new DefaultCodeVerifier(codeGenerator, timeProvider);

    @Nullable
    private final StringRedisTemplate redisTemplate;

    /**
     * Spring injects the app-wide auto-configured {@code StringRedisTemplate}.
     * Declared {@code Nullable} so the in-memory fallback engages cleanly if a
     * future profile has no Redis bean; replay prevention still functions.
     */
    public TotpService(@Nullable StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public String generateSecret() {
        String secret = secretGenerator.generate();
        log.debug("TOTP secret generated");
        return secret;
    }

    public String buildOtpAuthUri(String secret, String email, String issuer) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                issuer, email, secret, issuer);
    }

    /**
     * Verify a code against a secret WITHOUT replay protection.
     *
     * <p>Used for enrollment / setup-verification flows where the same code may
     * legitimately be submitted more than once and there is no authenticated
     * login to protect. Login and MFA-step flows must use
     * {@link #verifyCodeForUser(UUID, String, String)} instead.
     */
    public boolean verifyCode(String secret, String code) {
        try {
            boolean valid = codeVerifier.isValidCode(secret, code);
            log.debug("TOTP code verification result: {}", valid);
            return valid;
        } catch (Exception e) {
            log.error("TOTP verification error", e);
            return false;
        }
    }

    /**
     * S13 — verify a code with single-use (anti-replay) enforcement bound to a user.
     *
     * <p>The code must (a) be cryptographically valid for {@code secret} within
     * the current acceptance window AND (b) not have been consumed before for
     * that user. On the first successful verify the matched time-step is marked
     * consumed (TTL-bounded); any later submission of the SAME code while still
     * in-window is rejected as a replay.
     *
     * @return {@code true} if the code is valid and being used for the first time;
     *         {@code false} if it is invalid OR a replay of an already-consumed code.
     */
    public boolean verifyCodeForUser(UUID userId, String secret, String code) {
        long matchedStep = findMatchingTimeStep(secret, code);
        if (matchedStep < 0) {
            log.debug("TOTP code did not match any in-window time-step");
            return false;
        }
        boolean firstUse = markConsumed(userId, matchedStep);
        if (!firstUse) {
            log.warn("S13: TOTP replay rejected for user={} timeStep={}", userId, matchedStep);
            return false;
        }
        return true;
    }

    /**
     * Determine which time-step (counter = floorDiv(epochSeconds, period)) a
     * submitted code matches, scanning the same {@code [-discrepancy, +discrepancy]}
     * window the verifier uses. Returns the matched step, or {@code -1} if none.
     *
     * <p>The bundled {@link DefaultCodeVerifier} only returns a boolean, so we
     * recompute the per-step codes here to learn the exact step. We intentionally
     * scan oldest-to-newest and return the FIRST match: the oldest in-window step
     * is the one most likely to be the code's true issuing step (an attacker
     * replaying late still maps deterministically to the same step), so the
     * consumed marker is precise.
     */
    long findMatchingTimeStep(String secret, String code) {
        if (secret == null || code == null) {
            return -1;
        }
        long currentBucket = Math.floorDiv(timeProvider.getTime(), (long) TIME_PERIOD_SECONDS);
        for (int offset = -ALLOWED_DISCREPANCY; offset <= ALLOWED_DISCREPANCY; offset++) {
            long step = currentBucket + offset;
            try {
                String expected = codeGenerator.generate(secret, step);
                if (constantTimeEquals(expected, code)) {
                    return step;
                }
            } catch (CodeGenerationException e) {
                log.error("TOTP code generation error during step match", e);
                return -1;
            }
        }
        return -1;
    }

    /**
     * Atomically record {@code (userId, timeStep)} as consumed.
     *
     * @return {@code true} if this is the first time the pair is seen (code may
     *         be accepted); {@code false} if it was already consumed (replay).
     */
    private boolean markConsumed(UUID userId, long timeStep) {
        String key = CONSUMED_KEY_PREFIX + userId + ":" + timeStep;
        if (redisTemplate != null) {
            try {
                // SET key 1 EX <ttl> NX — atomic + multi-instance safe.
                Boolean wasSet = redisTemplate.opsForValue()
                        .setIfAbsent(key, "1", CONSUMED_TTL);
                if (wasSet != null) {
                    return wasSet; // true = newly set (first use); false = already present (replay)
                }
                // Null is unexpected; fall through to in-memory to fail safe.
                log.warn("S13: Redis setIfAbsent returned null for key={}, using fallback", key);
            } catch (Exception e) {
                log.warn("S13: Redis unavailable for replay check, falling back to in-memory: {}",
                        e.getMessage());
            }
        }
        return markConsumedFallback(key);
    }

    /** Bounded in-memory fallback with lazy TTL eviction (mirrors AntiReplayFilter). */
    private boolean markConsumedFallback(String key) {
        cleanupFallbackIfNeeded();
        long now = System.currentTimeMillis();
        long ttlMs = CONSUMED_TTL.toMillis();

        if (fallbackConsumed.size() >= MAX_FALLBACK_ENTRIES && !fallbackConsumed.containsKey(key)) {
            long cutoff = now - (ttlMs / 2);
            fallbackConsumed.entrySet().removeIf(e -> e.getValue() < cutoff);
        }

        // Treat an expired prior entry as absent so the marker still self-expires.
        Long expiresAt = fallbackConsumed.get(key);
        if (expiresAt != null && expiresAt > now) {
            return false; // still-live marker = replay
        }
        fallbackConsumed.put(key, now + ttlMs);
        return true;
    }

    private void cleanupFallbackIfNeeded() {
        long now = System.currentTimeMillis();
        long last = lastFallbackCleanup.get();
        if (now - last > 60_000L && lastFallbackCleanup.compareAndSet(last, now)) {
            fallbackConsumed.entrySet().removeIf(entry -> entry.getValue() < now);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] ab = a.getBytes();
        byte[] bb = b.getBytes();
        if (ab.length != bb.length) {
            return false;
        }
        return MessageDigest.isEqual(ab, bb);
    }
}
