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
        if (path.contains("/auth/login")) {
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
