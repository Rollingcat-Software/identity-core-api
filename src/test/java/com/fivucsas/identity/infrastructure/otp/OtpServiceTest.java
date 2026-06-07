package com.fivucsas.identity.infrastructure.otp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import com.fivucsas.identity.exception.RateLimitExceededException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Pins NIST 800-63B §5.1.1.2 / §5.2.2 per-code attempt counter on
 * {@link OtpService}. The 5th consecutive wrong guess against a single
 * issued OTP must invalidate the code server-side, regardless of TTL.
 *
 * <p>Tests run with mocked {@link StringRedisTemplate} so they exercise
 * exactly the OtpService branching without spinning up Redis. Counter
 * state is simulated by a plain in-memory {@link Map}.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("OtpService — per-code attempt counter (NIST 800-63B)")
class OtpServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private OtpService otpService;

    private static final String KEY = "otp:email:user-1";
    private static final String CORRECT = "123456";
    private static final String WRONG = "999999";

    private Map<String, Long> counterStore;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        // OTP itself is always present and equal to CORRECT. Tests that need
        // a "no OTP" state override this in-line.
        when(valueOperations.get(KEY)).thenReturn(CORRECT);

        // Simulate Redis INCR semantics on the :attempts companion key so
        // we can drive the counter past MAX_ATTEMPTS without a real Redis.
        counterStore = new HashMap<>();
        when(valueOperations.increment(anyString())).thenAnswer(inv -> {
            String k = inv.getArgument(0);
            long v = counterStore.getOrDefault(k, 0L) + 1L;
            counterStore.put(k, v);
            return v;
        });
    }

    @Nested
    @DisplayName("5-strike invalidation")
    class FiveStrikeInvalidation {

        @Test
        @DisplayName("4 wrong guesses leave the OTP intact and report shrinking remaining attempts")
        void fourMismatches_ShouldNotInvalidateOtp() {
            for (int i = 1; i <= 4; i++) {
                OtpService.ValidationResult r = otpService.validateWithResult(KEY, WRONG);
                assertThat(r.isValid()).isFalse();
                assertThat(r.isExhausted()).isFalse();
                assertThat(r.getRemainingAttempts())
                        .as("after %d wrong guess(es) with MAX_ATTEMPTS=5", i)
                        .isEqualTo(5L - i);
            }
            // OTP itself must NOT have been deleted yet.
            verify(redisTemplate, never()).delete(eq(KEY));
        }

        @Test
        @DisplayName("5th wrong guess invalidates the OTP and returns OTP_ATTEMPTS_EXHAUSTED")
        void fifthMismatch_ShouldInvalidateOtpAndReportExhausted() {
            OtpService.ValidationResult last = null;
            for (int i = 1; i <= 5; i++) {
                last = otpService.validateWithResult(KEY, WRONG);
            }
            assertThat(last).isNotNull();
            assertThat(last.isValid()).isFalse();
            assertThat(last.isExhausted())
                    .as("5th mismatch must trip OTP_ATTEMPTS_EXHAUSTED")
                    .isTrue();
            assertThat(last.getRemainingAttempts()).isZero();

            // The OTP and its attempt counter must both be deleted on the 5th strike.
            verify(redisTemplate, atLeastOnce()).delete(eq(KEY));
            verify(redisTemplate, atLeastOnce()).delete(eq(KEY + ":attempts"));
        }

        @Test
        @DisplayName("validate(...) returns false on the 5th mismatch (boolean back-compat)")
        void validate_ShouldReturnFalseOnExhaustion() {
            for (int i = 1; i <= 4; i++) {
                otpService.validate(KEY, WRONG);
            }
            assertThat(otpService.validate(KEY, WRONG)).isFalse();
            verify(redisTemplate, atLeastOnce()).delete(eq(KEY));
        }

        @Test
        @DisplayName("First mismatch sets a TTL on the counter so it expires with the OTP")
        void firstMismatch_ShouldSetTtlOnAttemptsKey() {
            otpService.validateWithResult(KEY, WRONG);
            // Counter expiration must be set on the very first INCR (which
            // returns 1) — without this the counter would live forever.
            verify(redisTemplate)
                    .expire(eq(KEY + ":attempts"), any(Duration.class));
        }
    }

    @Nested
    @DisplayName("Successful match resets counter")
    class SuccessfulMatch {

        @Test
        @DisplayName("Correct code before exhaustion clears OTP + counter atomically")
        void successBeforeExhaustion_ShouldClearOtpAndCounter() {
            // Burn 3 wrong guesses to pollute the counter.
            otpService.validateWithResult(KEY, WRONG);
            otpService.validateWithResult(KEY, WRONG);
            otpService.validateWithResult(KEY, WRONG);

            OtpService.ValidationResult ok = otpService.validateWithResult(KEY, CORRECT);
            assertThat(ok.isValid()).isTrue();
            assertThat(ok.isExhausted()).isFalse();

            // Both keys must be deleted so a stale guess against the consumed
            // OTP returns "not found" rather than leaking attempt state.
            verify(redisTemplate, atLeastOnce()).delete(eq(KEY));
            verify(redisTemplate, atLeastOnce()).delete(eq(KEY + ":attempts"));
        }
    }

    @Nested
    @DisplayName("generate(...) starts each new code with a fresh counter")
    class FreshCounterPerOtp {

        @Test
        @DisplayName("generate() clears any stale counter so re-issuing gives full attempt budget")
        void generate_ShouldClearStaleAttemptsCounter() {
            otpService.generate(KEY);
            // generate must always wipe the companion :attempts key — otherwise
            // a user who burned 4 attempts on a previous code, then asked for
            // a new one, would inherit only 1 attempt against the fresh code.
            verify(redisTemplate).delete(eq(KEY + ":attempts"));
        }
    }

    @Nested
    @DisplayName("Per-identifier OTP-send throttle (acquireSendSlot)")
    class SendThrottle {

        private static final String SEND_KEY = "2fa-sms:user-1";
        private static final String SEND_COUNTER = SEND_KEY + ":sends";

        @Test
        @DisplayName("acquireSendSlot allows up to MAX_SENDS and throttles the next (per-identifier)")
        void acquireSendSlot_WhenOverCap_ShouldThrowRateLimitExceeded() {
            // First MAX_SENDS sends are allowed (counter 1..3 ≤ 3).
            for (int i = 1; i <= OtpService.MAX_SENDS; i++) {
                final int n = i;
                assertThatCode(() -> otpService.acquireSendSlot(SEND_KEY))
                        .as("send #%d of MAX_SENDS=%d must be allowed", n, OtpService.MAX_SENDS)
                        .doesNotThrowAnyException();
            }
            // The (MAX_SENDS+1)th send trips the throttle → 429.
            assertThatExceptionOfType(RateLimitExceededException.class)
                    .isThrownBy(() -> otpService.acquireSendSlot(SEND_KEY));
        }

        @Test
        @DisplayName("acquireSendSlot sets a TTL on the send counter on the first send so it self-expires")
        void acquireSendSlot_OnFirstSend_ShouldSetTtl() {
            otpService.acquireSendSlot(SEND_KEY);
            verify(redisTemplate).expire(eq(SEND_COUNTER), any(Duration.class));
        }

        @Test
        @DisplayName("acquireSendSlot fails OPEN when Redis is unavailable (never blocks a legitimate send)")
        void acquireSendSlot_WhenRedisDown_ShouldNotThrow() {
            when(valueOperations.increment(eq(SEND_COUNTER)))
                    .thenThrow(new RuntimeException("redis down"));

            assertThatCode(() -> otpService.acquireSendSlot(SEND_KEY))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("No OTP at key")
    class NoOtpStored {

        @Test
        @DisplayName("Missing OTP returns invalid without touching the attempts counter")
        void missingOtp_ShouldReturnInvalidWithoutIncrementing() {
            when(valueOperations.get(KEY)).thenReturn(null);

            OtpService.ValidationResult r = otpService.validateWithResult(KEY, WRONG);
            assertThat(r.isValid()).isFalse();
            assertThat(r.isExhausted()).isFalse();
            // No INCR — we don't want to leak whether a code was ever issued
            // by exposing a counter that started ticking.
            verify(valueOperations, never()).increment(anyString());
        }
    }
}
