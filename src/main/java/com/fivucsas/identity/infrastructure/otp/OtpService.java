package com.fivucsas.identity.infrastructure.otp;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

/**
 * Issues and validates one-time passcodes (email / SMS / generic) backed by
 * Redis.
 *
 * <p><b>NIST 800-63B §5.1.1.2 / §5.2.2 — per-code attempt counter.</b> Without
 * one, the only check on online OTP guessing is the IP rate limiter (~30/min);
 * over a 5-minute TTL an attacker can run ~150 guesses against a 10⁶ keyspace,
 * which lifts a single-OTP brute-force from "rounding error" to "1.5 in 10⁴".
 * NIST mandates locking the code after a small number of consecutive failures
 * (commonly 5). This service enforces 5 strikes server-side: the 5th wrong
 * guess deletes the OTP regardless of TTL, so the only way forward is a fresh
 * {@link #generate(String)} call (which both resets the counter and re-arms
 * the per-IP limiter on the send endpoint). On a successful match, the OTP
 * and its counter are cleared atomically so a subsequent wrong code on a
 * stale key returns a clean "not found" rather than leaking ghost attempts.
 *
 * <p>Counter is stored at {@code <key>:attempts} with the same TTL as the
 * OTP itself, so an expired OTP's counter is GC'd automatically — no Redis
 * housekeeping required.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OtpService {

    private final StringRedisTemplate redisTemplate;

    private static final int OTP_LENGTH = 6;
    private static final Duration OTP_TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Maximum consecutive wrong guesses against a single issued OTP before the
     * code is invalidated server-side. NIST 800-63B recommends 3-5; we pick 5
     * to absorb legitimate fat-finger / SMS-truncation typos without forcing
     * a fresh send. The 5th mismatch consumes the code.
     */
    static final int MAX_ATTEMPTS = 5;

    private static final String ATTEMPTS_SUFFIX = ":attempts";

    public String generate(String key) {
        String code = generateCode();
        redisTemplate.opsForValue().set(key, code, OTP_TTL);
        // Clear any stale counter from a previous (expired or exhausted) OTP
        // so the freshly generated code starts at zero. Otherwise a user who
        // burned 4 attempts on a previous code, then re-requested, would only
        // have 1 attempt on the new one — that's a footgun, not a feature.
        redisTemplate.delete(key + ATTEMPTS_SUFFIX);
        log.debug("OTP generated for key: {}", key);
        return code;
    }

    /**
     * Validate {@code code} against the OTP stored at {@code key}.
     *
     * <p>Returns {@code false} on any failure (no OTP, mismatch, or attempts
     * exhausted) for backwards compatibility with existing call-sites that
     * surface a generic "Invalid or expired OTP" message. Callers that want
     * to render the remaining-attempts hint should use
     * {@link #validateWithResult(String, String)} instead.</p>
     */
    public boolean validate(String key, String code) {
        return validateWithResult(key, code).isValid();
    }

    /**
     * Validate {@code code} against the OTP stored at {@code key} and return a
     * structured result so the controller can surface remaining attempts /
     * exhaustion to the user.
     */
    public ValidationResult validateWithResult(String key, String code) {
        String stored = redisTemplate.opsForValue().get(key);
        if (stored == null) {
            log.debug("OTP not found or expired for key: {}", key);
            return ValidationResult.notFound();
        }

        if (stored.equals(code)) {
            // Clear OTP and its attempt counter together so a stale guess
            // against the consumed key returns a clean "not found".
            redisTemplate.delete(key);
            redisTemplate.delete(key + ATTEMPTS_SUFFIX);
            log.debug("OTP validated and consumed for key: {}", key);
            return ValidationResult.valid();
        }

        // Mismatch: increment attempt counter and decide whether to invalidate.
        // We use INCR so two parallel guesses cannot race past MAX_ATTEMPTS.
        // On the very first INCR the key has no TTL; we set one immediately so
        // the counter expires alongside the OTP itself.
        String attemptsKey = key + ATTEMPTS_SUFFIX;
        Long attempts = redisTemplate.opsForValue().increment(attemptsKey);
        if (attempts != null && attempts == 1L) {
            redisTemplate.expire(attemptsKey, OTP_TTL);
        }
        long attemptsNow = attempts == null ? 1L : attempts;
        long remaining = Math.max(0L, MAX_ATTEMPTS - attemptsNow);

        if (attemptsNow >= MAX_ATTEMPTS) {
            // Burn the OTP. A fresh /send is now the only path forward.
            redisTemplate.delete(key);
            redisTemplate.delete(attemptsKey);
            log.warn(
                    "OTP attempts exhausted for key: {} (attempts={}, max={})",
                    key, attemptsNow, MAX_ATTEMPTS);
            return ValidationResult.exhausted();
        }

        log.debug(
                "OTP validation failed for key: {} (attempts={}, remaining={})",
                key, attemptsNow, remaining);
        return ValidationResult.invalid(remaining);
    }

    public void invalidate(String key) {
        redisTemplate.delete(key);
        redisTemplate.delete(key + ATTEMPTS_SUFFIX);
    }

    private String generateCode() {
        int bound = (int) Math.pow(10, OTP_LENGTH);
        int code = RANDOM.nextInt(bound);
        return String.format("%0" + OTP_LENGTH + "d", code);
    }

    /**
     * Outcome of a {@link #validateWithResult(String, String)} call.
     *
     * <p>Three terminal states:
     * <ul>
     *   <li>{@link #valid()} — code matched; OTP consumed.</li>
     *   <li>{@link #invalid(long)} — code did not match; {@code remainingAttempts}
     *       guesses left before exhaustion.</li>
     *   <li>{@link #exhausted()} — too many wrong guesses; OTP has been
     *       deleted server-side.</li>
     *   <li>{@link #notFound()} — no OTP found at the key (never issued, TTL
     *       expired, or already consumed). Treated as a generic mismatch by
     *       callers; no attempt counter is touched.</li>
     * </ul>
     */
    public static final class ValidationResult {
        private final boolean valid;
        private final boolean exhausted;
        private final long remainingAttempts;

        private ValidationResult(boolean valid, boolean exhausted, long remainingAttempts) {
            this.valid = valid;
            this.exhausted = exhausted;
            this.remainingAttempts = remainingAttempts;
        }

        public static ValidationResult valid() {
            return new ValidationResult(true, false, MAX_ATTEMPTS);
        }

        public static ValidationResult invalid(long remainingAttempts) {
            return new ValidationResult(false, false, remainingAttempts);
        }

        public static ValidationResult exhausted() {
            return new ValidationResult(false, true, 0);
        }

        /**
         * No OTP found at the key. Reported as invalid-with-zero-remaining so
         * the controller can return a generic "invalid or expired" without
         * leaking whether a code was ever issued.
         */
        public static ValidationResult notFound() {
            return new ValidationResult(false, false, 0);
        }

        public boolean isValid() {
            return valid;
        }

        public boolean isExhausted() {
            return exhausted;
        }

        public long getRemainingAttempts() {
            return remainingAttempts;
        }
    }
}
