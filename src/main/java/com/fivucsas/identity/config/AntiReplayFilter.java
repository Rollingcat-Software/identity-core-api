package com.fivucsas.identity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Anti-replay filter for biometric and NFC submission endpoints.
 *
 * Checks the X-Request-Nonce header on sensitive POST endpoints.
 * If present, ensures the nonce has not been used before within the TTL window.
 * This prevents replay attacks where an intercepted biometric submission
 * is re-sent by an attacker.
 *
 * Uses Redis for distributed nonce tracking (multi-instance safe).
 * Falls back to bounded in-memory store when Redis is unavailable.
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class AntiReplayFilter {

    private final RedisTemplate<String, String> redisTemplate;

    private static final Set<String> PROTECTED_PATHS = Set.of(
            "/api/v1/biometric/enroll",
            "/api/v1/biometric/verify",
            "/api/v1/biometric/search",
            "/api/v1/nfc/enroll",
            "/api/v1/nfc/verify"
    );

    private static final String NONCE_HEADER = "X-Request-Nonce";
    private static final String REDIS_NONCE_PREFIX = "antireplay:nonce:";
    // 5-minute window for nonce validity
    private static final long NONCE_TTL_MS = 300_000L;
    private static final Duration NONCE_TTL = Duration.ofMillis(NONCE_TTL_MS);

    // In-memory fallback nonce store (bounded)
    private static final int MAX_FALLBACK_NONCES = 50_000;
    private final ConcurrentHashMap<String, Long> fallbackNonces = new ConcurrentHashMap<>();
    private final AtomicLong lastFallbackCleanup = new AtomicLong(System.currentTimeMillis());

    @Bean
    public OncePerRequestFilter antiReplayOncePerRequestFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain filterChain)
                    throws ServletException, IOException {

                String path = request.getRequestURI();
                String method = request.getMethod();

                // Only check POST requests to protected paths
                if (!"POST".equalsIgnoreCase(method)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                boolean isProtected = PROTECTED_PATHS.stream()
                        .anyMatch(path::startsWith);

                if (!isProtected) {
                    filterChain.doFilter(request, response);
                    return;
                }

                String nonce = request.getHeader(NONCE_HEADER);

                // If nonce header is present, validate it
                if (nonce != null && !nonce.isBlank()) {
                    if (isNonceDuplicate(nonce)) {
                        log.warn("Anti-replay: duplicate nonce detected nonce={} ip={} path={}",
                                nonce, request.getRemoteAddr(), path);
                        response.setStatus(409);
                        response.setContentType("application/json");
                        response.getWriter().write(
                                "{\"status\":409,\"error\":\"Conflict\",\"message\":\"Duplicate request detected. This submission has already been processed.\"}");
                        return;
                    }
                }

                filterChain.doFilter(request, response);
            }
        };
    }

    /**
     * Check if nonce is duplicate using Redis (primary) or in-memory fallback.
     */
    private boolean isNonceDuplicate(String nonce) {
        try {
            // Try Redis first (distributed, multi-instance safe)
            String redisKey = REDIS_NONCE_PREFIX + nonce;
            Boolean wasSet = redisTemplate.opsForValue().setIfAbsent(redisKey, "1", NONCE_TTL);
            if (Boolean.FALSE.equals(wasSet)) {
                return true; // Nonce already existed in Redis = duplicate
            }
            return false; // New nonce, successfully stored
        } catch (Exception e) {
            log.warn("Redis unavailable for anti-replay, falling back to in-memory: {}", e.getMessage());
            return isNonceDuplicateFallback(nonce);
        }
    }

    /**
     * In-memory fallback for nonce deduplication (bounded).
     */
    private boolean isNonceDuplicateFallback(String nonce) {
        cleanupFallbackIfNeeded();

        // Enforce size limit
        if (fallbackNonces.size() >= MAX_FALLBACK_NONCES && !fallbackNonces.containsKey(nonce)) {
            // Map is full — evict oldest entries aggressively
            long cutoff = System.currentTimeMillis() - (NONCE_TTL_MS / 2);
            fallbackNonces.entrySet().removeIf(e -> e.getValue() < cutoff);
        }

        Long previousTimestamp = fallbackNonces.putIfAbsent(nonce, System.currentTimeMillis());
        return previousTimestamp != null; // Non-null means already existed = duplicate
    }

    private void cleanupFallbackIfNeeded() {
        long now = System.currentTimeMillis();
        long last = lastFallbackCleanup.get();
        if (now - last > 60_000L && lastFallbackCleanup.compareAndSet(last, now)) {
            long cutoff = now - NONCE_TTL_MS;
            fallbackNonces.entrySet().removeIf(entry -> entry.getValue() < cutoff);
        }
    }
}
