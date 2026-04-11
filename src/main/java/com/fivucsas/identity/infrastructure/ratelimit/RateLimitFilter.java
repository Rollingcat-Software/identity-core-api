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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Filter for rate limiting HTTP requests using Redis.
 * Implements token bucket algorithm for distributed rate limiting.
 * Falls back to in-memory rate limiting when Redis is unavailable.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    private final RedisTemplate<String, String> redisTemplate;

    // Rate limit: 100 requests per minute per IP
    private static final int MAX_REQUESTS = 100;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    // Sensitive endpoints that must fail-closed
    private static final java.util.Set<String> SENSITIVE_PATHS = java.util.Set.of(
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password"
    );

    // In-memory fallback rate limiter (bounded)
    private static final int MAX_FALLBACK_ENTRIES = 10_000;
    private final ConcurrentHashMap<String, FallbackBucket> fallbackBuckets = new ConcurrentHashMap<>();
    private final AtomicLong lastFallbackCleanup = new AtomicLong(System.currentTimeMillis());
    private static final long FALLBACK_CLEANUP_INTERVAL_MS = 60_000L;

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
                long retryAfterSeconds = WINDOW.getSeconds();
                log.warn("Rate limit exceeded for client: {} on path: {}", clientId, path);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
                response.setHeader("X-RateLimit-Retry-After", String.valueOf(retryAfterSeconds));
                response.setContentType("application/json");
                response.getWriter().write(
                        "{\"error\": \"Rate limit exceeded\", \"retryAfterSeconds\": " + retryAfterSeconds + "}");
                return;
            }

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("Redis unavailable for rate limiting: {}", e.getMessage());

            // For sensitive auth endpoints, use in-memory fallback instead of failing open
            if (isSensitivePath(path)) {
                if (fallbackRateLimitExceeded(clientId, path)) {
                    long retryAfterSeconds = WINDOW.getSeconds();
                    log.warn("Fallback rate limit exceeded for client: {} on path: {}", clientId, path);
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
                    response.setContentType("application/json");
                    response.getWriter().write(
                            "{\"error\": \"Rate limit exceeded\", \"retryAfterSeconds\": " + retryAfterSeconds + "}");
                    return;
                }
            }

            filterChain.doFilter(request, response);
        }
    }

    /**
     * In-memory fallback rate limiter for when Redis is unavailable.
     * Uses a bounded ConcurrentHashMap with periodic cleanup.
     */
    private boolean fallbackRateLimitExceeded(String clientId, String path) {
        cleanupFallbackIfNeeded();

        // Enforce size limit to prevent memory DoS
        String key = clientId + ":" + path;
        if (fallbackBuckets.size() >= MAX_FALLBACK_ENTRIES && !fallbackBuckets.containsKey(key)) {
            // If map is full and this is a new key, reject (fail-closed)
            log.warn("Fallback rate limit map is full, rejecting new client: {}", clientId);
            return true;
        }

        FallbackBucket bucket = fallbackBuckets.computeIfAbsent(key, k -> new FallbackBucket());
        return bucket.incrementAndCheck(MAX_REQUESTS, WINDOW.toMillis());
    }

    private void cleanupFallbackIfNeeded() {
        long now = System.currentTimeMillis();
        long last = lastFallbackCleanup.get();
        if (now - last > FALLBACK_CLEANUP_INTERVAL_MS && lastFallbackCleanup.compareAndSet(last, now)) {
            long cutoff = now - WINDOW.toMillis();
            fallbackBuckets.entrySet().removeIf(e -> e.getValue().windowStart < cutoff);
        }
    }

    private boolean isSensitivePath(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(path::startsWith);
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

    /**
     * Simple in-memory rate limit bucket with sliding window.
     */
    private static class FallbackBucket {
        volatile long windowStart = System.currentTimeMillis();
        final AtomicInteger count = new AtomicInteger(0);

        boolean incrementAndCheck(int maxRequests, long windowMs) {
            long now = System.currentTimeMillis();
            if (now - windowStart > windowMs) {
                // Reset window
                windowStart = now;
                count.set(1);
                return false;
            }
            return count.incrementAndGet() > maxRequests;
        }
    }
}
