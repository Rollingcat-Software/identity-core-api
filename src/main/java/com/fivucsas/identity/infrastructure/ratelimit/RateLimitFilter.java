package com.fivucsas.identity.infrastructure.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

/**
 * Filter for rate limiting HTTP requests using Redis.
 * Implements token bucket algorithm for distributed rate limiting.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    private final RedisTemplate<String, String> redisTemplate;

    // Rate limit: 100 requests per minute per IP
    private static final int MAX_REQUESTS = 100;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        // Skip rate limiting for health checks and actuator endpoints
        if (shouldSkipRateLimiting(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientId = getClientIdentifier(request);
        String key = "rate_limit:" + clientId + ":" + path;

        try {
            Long requests = redisTemplate.opsForValue().increment(key);

            if (requests == null) {
                requests = 0L;
            }

            // Set expiry on first request
            if (requests == 1) {
                redisTemplate.expire(key, WINDOW);
            }

            // Add rate limit headers
            response.setHeader("X-RateLimit-Limit", String.valueOf(MAX_REQUESTS));
            response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, MAX_REQUESTS - requests)));

            if (requests > MAX_REQUESTS) {
                log.warn("Rate limit exceeded for client: {} on path: {}", clientId, path);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setHeader("X-RateLimit-Retry-After", String.valueOf(WINDOW.getSeconds()));
                response.getWriter().write("{\"error\": \"Rate limit exceeded. Please try again later.\"}");
                response.setContentType("application/json");
                return;
            }

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("Error in rate limiting: {}", e.getMessage());
            // On error, allow the request through (fail open)
            filterChain.doFilter(request, response);
        }
    }

    private String getClientIdentifier(HttpServletRequest request) {
        // Try X-Forwarded-For header first (for proxies/load balancers)
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        // Fallback to remote address
        return request.getRemoteAddr();
    }

    private boolean shouldSkipRateLimiting(String path) {
        return path.startsWith("/actuator") ||
               path.startsWith("/swagger") ||
               path.startsWith("/v3/api-docs") ||
               path.equals("/health");
    }
}
