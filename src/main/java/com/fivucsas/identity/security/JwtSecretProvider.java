package com.fivucsas.identity.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

/**
 * Secure JWT secret provider that validates and manages JWT signing keys.
 *
 * Security Requirements:
 * - JWT secret MUST be provided via JWT_SECRET environment variable (production)
 * - Fallback to jwt.secret property for testing environments
 * - Minimum 256 bits (32 characters) for HMAC-SHA256
 * - Never log or expose the actual secret value
 * - Fail fast on startup if secret is invalid
 *
 * Usage:
 * Set environment variable before starting:
 * export JWT_SECRET="your-secure-base64-encoded-secret-minimum-32-characters"
 *
 * @author FIVUCSAS Team
 * @since 1.0.0
 */
@Component
@Slf4j
public class JwtSecretProvider {

    private static final int MINIMUM_SECRET_LENGTH = 32;
    private static final String ENV_VAR_NAME = "JWT_SECRET";

    @Value("${jwt.secret:}")
    private String configSecret;

    private String secret;

    /**
     * Validates and loads JWT secret on application startup.
     * Fails fast if secret is missing or invalid.
     *
     * @throws IllegalStateException if JWT secret is not properly configured
     */
    @PostConstruct
    public void initialize() {
        log.info("Initializing JWT secret provider...");

        // First try environment variable (preferred for production)
        secret = System.getenv(ENV_VAR_NAME);

        // Fallback to Spring property (for tests and local development)
        if (secret == null || secret.trim().isEmpty()) {
            if (configSecret != null && !configSecret.trim().isEmpty()) {
                secret = configSecret;
                log.info("SECURITY: JWT secret loaded from application property (suitable for test/dev only)");
            } else {
                String errorMessage = String.format(
                    "CRITICAL SECURITY ERROR: %s environment variable is not set. " +
                    "Application cannot start without a valid JWT secret. " +
                    "Please set %s environment variable with a base64-encoded secret of minimum %d characters.",
                    ENV_VAR_NAME, ENV_VAR_NAME, MINIMUM_SECRET_LENGTH
                );
                log.error(errorMessage);
                throw new IllegalStateException(errorMessage);
            }
        } else {
            log.info("SECURITY: JWT secret loaded from environment variable");
        }

        if (secret.length() < MINIMUM_SECRET_LENGTH) {
            String errorMessage = String.format(
                "CRITICAL SECURITY ERROR: JWT secret is too short. " +
                "Minimum length: %d characters, provided: %d characters. " +
                "Please use a stronger secret for production security.",
                MINIMUM_SECRET_LENGTH, secret.length()
            );
            log.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        }

        // Log success WITHOUT exposing the actual secret
        log.info("JWT secret provider initialized successfully. Secret length: {} characters", secret.length());
    }

    /**
     * Returns the validated JWT secret.
     *
     * @return the JWT secret for token signing/verification
     * @throws IllegalStateException if called before initialization
     */
    public String getSecret() {
        if (secret == null) {
            throw new IllegalStateException(
                "JWT secret not initialized. This should never happen if PostConstruct executed correctly."
            );
        }
        return secret;
    }

    /**
     * Validates if the secret meets security requirements.
     *
     * @return true if secret is valid and secure
     */
    public boolean isSecretValid() {
        return secret != null && secret.length() >= MINIMUM_SECRET_LENGTH;
    }
}
