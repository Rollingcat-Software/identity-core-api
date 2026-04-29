package com.fivucsas.identity.config;

import com.fivucsas.identity.exception.RateLimitExceededException;
import com.fivucsas.identity.security.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * AUDIT_2026-04-28_SECURITY.md SEC-P1 #4: confirms POST /auth/mfa/step now
 * passes through the MFA_STEP rate-limit bucket and surfaces a 429 with
 * Retry-After when the budget is exhausted. Pre-fix the path matched no
 * branch in {@link RateLimitInterceptor} and brute-force was unthrottled.
 *
 * Uses the real {@link RateLimitService} (Bucket4j in-memory buckets) so
 * the test exercises the actual token-bucket behavior, not just the
 * branch wiring.
 */
@DisplayName("RateLimitInterceptor — MFA step bucket (SEC-P1 #4)")
class RateLimitInterceptorMfaStepTest {

    private RateLimitService rateLimitService;
    private RateLimitInterceptor interceptor;

    @BeforeEach
    void setUp() {
        rateLimitService = new RateLimitService();
        interceptor = new RateLimitInterceptor(rateLimitService);
    }

    @Test
    @DisplayName("First /auth/mfa/step request from a new IP is allowed")
    void mfaStep_FirstAttempt_ShouldBeAllowed() throws Exception {
        HttpServletRequest req = mockRequest("/api/v1/auth/mfa/step", "10.0.0.1");
        HttpServletResponse res = new MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(req, res, new Object());

        assertThat(allowed).isTrue();
    }

    @Test
    @DisplayName("31st /auth/mfa/step in the same minute throws 429 with Retry-After")
    void mfaStep_OverLimit_ShouldThrow429WithRetryAfter() throws Exception {
        HttpServletRequest req = mockRequest("/api/v1/auth/mfa/step", "10.0.0.2");
        // Burn the bucket — 30/min cap.
        for (int i = 0; i < 30; i++) {
            interceptor.preHandle(req, new MockHttpServletResponse(), new Object());
        }

        // 31st attempt — must be blocked AND the Retry-After header must be
        // populated on the response (RFC 6585 §4).
        MockHttpServletResponse blockedRes = new MockHttpServletResponse();
        assertThatThrownBy(() -> interceptor.preHandle(req, blockedRes, new Object()))
                .isInstanceOf(RateLimitExceededException.class)
                .hasMessageContaining("MFA step");

        String retryAfter = blockedRes.getHeader("Retry-After");
        assertThat(retryAfter)
                .as("Retry-After header MUST be set on 429 per RFC 6585 §4")
                .isNotNull();
        assertThat(Long.parseLong(retryAfter))
                .as("Retry-After must be a non-negative integer (seconds)")
                .isGreaterThanOrEqualTo(0);
    }

    @Test
    @DisplayName("Different IPs get independent /auth/mfa/step buckets")
    void mfaStep_DifferentIps_ShouldGetSeparateBuckets() throws Exception {
        HttpServletRequest reqA = mockRequest("/api/v1/auth/mfa/step", "10.0.0.3");
        for (int i = 0; i < 30; i++) {
            interceptor.preHandle(reqA, new MockHttpServletResponse(), new Object());
        }

        // Same path, different IP — must still be allowed.
        HttpServletRequest reqB = mockRequest("/api/v1/auth/mfa/step", "10.0.0.4");
        boolean allowedB = interceptor.preHandle(reqB, new MockHttpServletResponse(), new Object());
        assertThat(allowedB).isTrue();
    }

    private HttpServletRequest mockRequest(String uri, String remoteAddr) {
        MockHttpServletRequest r = new MockHttpServletRequest();
        r.setRequestURI(uri);
        r.setRemoteAddr(remoteAddr);
        return r;
    }
}
