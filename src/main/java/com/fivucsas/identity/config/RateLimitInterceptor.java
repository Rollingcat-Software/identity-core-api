package com.fivucsas.identity.config;

import com.fivucsas.identity.exception.RateLimitExceededException;
import com.fivucsas.identity.security.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Interceptor for applying rate limiting to authentication endpoints.
 *
 * Applied to:
 * - /api/v1/auth/login
 * - /api/v1/auth/register
 * - /api/v1/auth/refresh
 *
 * @author FIVUCSAS Team
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {

    private final RateLimitService rateLimitService;

    @Override
    public boolean preHandle(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull Object handler) throws Exception {

        String path = request.getRequestURI();
        String clientIp = getClientIP(request);

        // Apply rate limiting based on endpoint
        if (path.contains("/auth/login") || path.contains("/oauth2/authorize/complete")) {
            // Hosted-login completion rides the same bucket as /auth/login because it
            // is the terminal step of a user-initiated login from an anonymous browser
            if (!rateLimitService.allowLoginAttempt(clientIp)) {
                long retryAfter = rateLimitService.getSecondsUntilRefill(
                    clientIp,
                    RateLimitService.RateLimitType.LOGIN
                );
                throw new RateLimitExceededException(
                    "Too many login attempts. Please try again later.",
                    retryAfter
                );
            }
        } else if (path.contains("/auth/register")) {
            if (!rateLimitService.allowRegistrationAttempt(clientIp)) {
                long retryAfter = rateLimitService.getSecondsUntilRefill(
                    clientIp,
                    RateLimitService.RateLimitType.REGISTRATION
                );
                throw new RateLimitExceededException(
                    "Too many registration attempts. Please try again later.",
                    retryAfter
                );
            }
        } else if (path.contains("/oauth2/clients/") && path.endsWith("/public")) {
            // Public branding endpoint — rate-limit against scraping/brute-force of client_ids
            if (!rateLimitService.allowBiometricVerification(clientIp)) {
                long retryAfter = rateLimitService.getSecondsUntilRefill(
                    clientIp,
                    RateLimitService.RateLimitType.BIOMETRIC
                );
                response.setHeader("Retry-After", String.valueOf(retryAfter));
                throw new RateLimitExceededException(
                    "Too many client metadata requests. Please wait and try again.",
                    retryAfter
                );
            }
        } else if (path.contains("/auth/mfa/qr-generate")) {
            // Defend against broken clients looping on QR generation.
            // Uses the biometric bucket (20/min per IP) — matches the expected legitimate rate.
            if (!rateLimitService.allowBiometricVerification(clientIp)) {
                long retryAfter = rateLimitService.getSecondsUntilRefill(
                    clientIp,
                    RateLimitService.RateLimitType.BIOMETRIC
                );
                response.setHeader("Retry-After", String.valueOf(retryAfter));
                throw new RateLimitExceededException(
                    "Too many QR generation requests. Please wait and try again.",
                    retryAfter
                );
            }
        }

        return true;
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
