package com.fivucsas.identity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Production security headers configuration.
 *
 * Adds standard security headers to all responses:
 * - X-Frame-Options: DENY (clickjacking protection)
 * - X-Content-Type-Options: nosniff (MIME sniffing prevention)
 * - X-XSS-Protection: 0 (deprecated, CSP preferred)
 * - Strict-Transport-Security (HSTS for HTTPS enforcement)
 * - Referrer-Policy (controls referrer information)
 * - Permissions-Policy (restricts browser features)
 * - Content-Security-Policy (XSS/injection prevention)
 * - Cache-Control for API responses
 */
@Configuration
public class SecurityHeadersConfig {

    @Value("${spring.profiles.active:dev}")
    private String activeProfile;

    @Bean
    public OncePerRequestFilter securityHeadersOncePerRequestFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain filterChain)
                    throws ServletException, IOException {

                // Clickjacking protection
                response.setHeader("X-Frame-Options", "DENY");

                // MIME type sniffing prevention
                response.setHeader("X-Content-Type-Options", "nosniff");

                // XSS Protection (modern browsers use CSP instead)
                response.setHeader("X-XSS-Protection", "0");

                // Referrer policy
                response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

                // Permissions policy — restrict sensitive features
                response.setHeader("Permissions-Policy",
                        "camera=(), microphone=(), geolocation=(), payment=()");

                // HSTS — enforce HTTPS for 1 year
                if (isProductionProfile()) {
                    response.setHeader("Strict-Transport-Security",
                            "max-age=31536000; includeSubDomains");

                    // Content-Security-Policy for API responses
                    response.setHeader("Content-Security-Policy",
                            "default-src 'none'; frame-ancestors 'none'");
                }

                // Prevent caching of API responses containing sensitive data
                String path = request.getRequestURI();
                if (path.startsWith("/api/")) {
                    response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                    response.setHeader("Pragma", "no-cache");
                }

                filterChain.doFilter(request, response);
            }

            private boolean isProductionProfile() {
                return "prod".equalsIgnoreCase(activeProfile)
                        || "production".equalsIgnoreCase(activeProfile);
            }
        };
    }
}
