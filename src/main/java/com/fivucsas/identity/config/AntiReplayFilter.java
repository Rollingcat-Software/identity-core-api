package com.fivucsas.identity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Anti-replay filter for biometric and NFC submission endpoints.
 *
 * Checks the X-Request-Nonce header on sensitive POST endpoints.
 * If present, ensures the nonce has not been used before within the TTL window.
 * This prevents replay attacks where an intercepted biometric submission
 * is re-sent by an attacker.
 *
 * The nonce is optional — if not provided, the request proceeds normally.
 * When provided, duplicate nonces within the 5-minute window are rejected.
 *
 * Note: The step-up authentication system already has its own challenge-response
 * nonce mechanism (StepUpChallengeService). This filter adds an additional
 * layer for general biometric/NFC submissions.
 */
@Configuration
@Slf4j
public class AntiReplayFilter {

    private static final Set<String> PROTECTED_PATHS = Set.of(
            "/api/v1/biometric/enroll",
            "/api/v1/biometric/verify",
            "/api/v1/biometric/search",
            "/api/v1/nfc/enroll",
            "/api/v1/nfc/verify"
    );

    private static final String NONCE_HEADER = "X-Request-Nonce";
    // 5-minute window for nonce validity
    private static final long NONCE_TTL_MS = 300_000L;

    // In-memory nonce store: nonce -> timestamp
    private final ConcurrentHashMap<String, Long> usedNonces = new ConcurrentHashMap<>();

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
                    // Cleanup expired nonces periodically
                    cleanupExpiredNonces();

                    Long previousTimestamp = usedNonces.putIfAbsent(nonce, System.currentTimeMillis());
                    if (previousTimestamp != null) {
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

    private void cleanupExpiredNonces() {
        long cutoff = System.currentTimeMillis() - NONCE_TTL_MS;
        usedNonces.entrySet().removeIf(entry -> entry.getValue() < cutoff);
    }
}
