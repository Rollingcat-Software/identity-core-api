package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Infrastructure adapter for audit logging.
 *
 * Implements the AuditLogPort using simple logging for now.
 * In production, this should write to a database or external audit service.
 *
 * NOTE: This is a placeholder implementation for Phase 4.
 *
 * Following principles:
 * - Adapter Pattern: Adapts logging to our port
 * - Dependency Inversion: Application defines port, infrastructure implements
 */
@Component
@Slf4j
public class AuditLogAdapter implements AuditLogPort {

    @Override
    public void logUserRegistered(String userId, String email, String ipAddress) {
        log.info("AUDIT: User registered - userId={}, email={}, ip={}", userId, email, ipAddress);
    }

    @Override
    public void logUserAuthenticated(String userId, String email, String ipAddress) {
        log.info("AUDIT: User authenticated - userId={}, email={}, ip={}", userId, email, ipAddress);
    }

    @Override
    public void logAuthenticationFailed(String email, String ipAddress, String reason) {
        log.warn("AUDIT: Authentication failed - email={}, ip={}, reason={}", email, ipAddress, reason);
    }

    @Override
    public void logUserLoggedOut(String userId, String email) {
        log.info("AUDIT: User logged out - userId={}, email={}", userId, email);
    }

    @Override
    public void logBiometricEnrollment(String userId, boolean success) {
        log.info("AUDIT: Biometric enrollment - userId={}, success={}", userId, success);
    }

    @Override
    public void logBiometricVerification(String userId, boolean success) {
        log.info("AUDIT: Biometric verification - userId={}, success={}", userId, success);
    }
}
