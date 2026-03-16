package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

/**
 * Infrastructure adapter for audit logging.
 *
 * Persists audit log entries to the database via AuditLogRepository.
 * Uses REQUIRES_NEW propagation to ensure audit entries are committed
 * even when the calling transaction rolls back (e.g., failed login).
 *
 * Following principles:
 * - Adapter Pattern: Adapts domain events to persistence
 * - Dependency Inversion: Application defines port, infrastructure implements
 * - Single Responsibility: Only handles audit log persistence
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditLogAdapter implements AuditLogPort {

    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(propagation = Propagation.REQUIRED)
    public void logUserRegistered(String userId, String email, String ipAddress) {
        log.info("AUDIT: User registered - userId={}, email={}, ip={}", userId, email, ipAddress);
        saveAuditLog("USER_CREATED", "USER", userId, true, ipAddress,
                Map.of("email", email));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logUserAuthenticated(String userId, String email, String ipAddress) {
        log.info("AUDIT: User authenticated - userId={}, email={}, ip={}", userId, email, ipAddress);
        saveAuditLog("USER_LOGIN", "USER", userId, true, ipAddress,
                Map.of("email", email));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logAuthenticationFailed(String email, String ipAddress, String reason) {
        log.warn("AUDIT: Authentication failed - email={}, ip={}, reason={}", email, ipAddress, reason);
        saveAuditLog("FAILED_LOGIN_ATTEMPT", "USER", null, false, ipAddress,
                Map.of("email", email, "reason", reason));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logUserLoggedOut(String userId, String email) {
        log.info("AUDIT: User logged out - userId={}, email={}", userId, email);
        saveAuditLog("USER_LOGOUT", "USER", userId, true, null,
                Map.of("email", email));
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logBiometricEnrollment(String userId, boolean success) {
        log.info("AUDIT: Biometric enrollment - userId={}, success={}", userId, success);
        saveAuditLog("BIOMETRIC_ENROLLMENT", "BIOMETRIC", userId, success, null, Map.of());
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logBiometricVerification(String userId, boolean success) {
        log.info("AUDIT: Biometric verification - userId={}, success={}", userId, success);
        saveAuditLog("BIOMETRIC_VERIFICATION", "BIOMETRIC", userId, success, null, Map.of());
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logSecurityEvent(String userId, String eventType, String ipAddress, String details) {
        log.info("AUDIT: Security event - userId={}, type={}, ip={}, details={}", userId, eventType, ipAddress, details);
        saveAuditLog(eventType, "SECURITY", userId, true, ipAddress,
                Map.of("details", details != null ? details : ""));
    }

    private void saveAuditLog(String action, String resourceType, String userId,
                              boolean success, String ipAddress, Map<String, Object> metadata) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .action(action)
                    .resourceType(resourceType)
                    .userId(userId != null ? UUID.fromString(userId) : null)
                    .resourceId(userId != null ? UUID.fromString(userId) : null)
                    .success(success)
                    .ipAddress(ipAddress)
                    .metadata(metadata)
                    .build();

            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to persist audit log: action={}, error={}", action, e.getMessage(), e);
        }
    }
}
