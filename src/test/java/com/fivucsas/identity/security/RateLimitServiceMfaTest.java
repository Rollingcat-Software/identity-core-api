package com.fivucsas.identity.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Phase 1.4 (AUDIT_2026-04-20) — MFA rate-limit buckets.
 *
 * <p>Caps mirror {@code RateLimitService#createMfa*Bucket()}:
 * <ul>
 *   <li>{@code allowMfaStepAttempt} — 10 per 10 min (brute-force guard)</li>
 *   <li>{@code allowMfaOtpSend}     — 3 per 10 min  (SMS/email cost guard)</li>
 *   <li>{@code allowMfaQrGenerate}  — 5 per 10 min  (enrollment abuse guard)</li>
 * </ul>
 */
class RateLimitServiceMfaTest {

    private RateLimitService rls;

    @BeforeEach
    void setUp() {
        rls = new RateLimitService();
    }

    @Test
    void mfaStep_AllowsTenThenBlocks() {
        String ip = "10.0.0.1";
        for (int i = 0; i < 10; i++) {
            assertThat(rls.allowMfaStepAttempt(ip)).as("attempt %d", i + 1).isTrue();
        }
        assertThat(rls.allowMfaStepAttempt(ip)).isFalse();
    }

    @Test
    void mfaOtpSend_AllowsThreeThenBlocks() {
        String ip = "10.0.0.2";
        assertThat(rls.allowMfaOtpSend(ip)).isTrue();
        assertThat(rls.allowMfaOtpSend(ip)).isTrue();
        assertThat(rls.allowMfaOtpSend(ip)).isTrue();
        assertThat(rls.allowMfaOtpSend(ip)).isFalse();
    }

    @Test
    void mfaQrGenerate_AllowsFiveThenBlocks() {
        String ip = "10.0.0.3";
        for (int i = 0; i < 5; i++) {
            assertThat(rls.allowMfaQrGenerate(ip)).isTrue();
        }
        assertThat(rls.allowMfaQrGenerate(ip)).isFalse();
    }

    @Test
    void mfaBuckets_AreIndependentPerIdentifier() {
        // Exhausting one session's bucket must not affect another.
        String a = "10.0.0.4";
        String b = "10.0.0.5";
        for (int i = 0; i < 3; i++) {
            rls.allowMfaOtpSend(a);
        }
        assertThat(rls.allowMfaOtpSend(a)).isFalse();
        assertThat(rls.allowMfaOtpSend(b)).isTrue();
    }

    @Test
    void mfaBuckets_AreIndependentPerType() {
        // Exhausting step bucket must not spill into otp or qr buckets.
        String ip = "10.0.0.6";
        for (int i = 0; i < 10; i++) {
            rls.allowMfaStepAttempt(ip);
        }
        assertThat(rls.allowMfaStepAttempt(ip)).isFalse();
        assertThat(rls.allowMfaOtpSend(ip)).isTrue();
        assertThat(rls.allowMfaQrGenerate(ip)).isTrue();
    }

    @Test
    void resetRateLimit_ClearsMfaBucket() {
        String ip = "10.0.0.7";
        for (int i = 0; i < 10; i++) {
            rls.allowMfaStepAttempt(ip);
        }
        assertThat(rls.allowMfaStepAttempt(ip)).isFalse();

        rls.resetRateLimit(ip, RateLimitService.RateLimitType.MFA_STEP);

        assertThat(rls.allowMfaStepAttempt(ip)).isTrue();
    }
}
