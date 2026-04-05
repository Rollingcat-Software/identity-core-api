package com.fivucsas.identity.application.port.output;

/**
 * Output port for audit logging operations.
 *
 * This interface defines the contract for logging security-relevant events.
 * Currently a placeholder for future implementation.
 *
 * Following principles:
 * - Dependency Inversion: Application defines the port, infrastructure implements
 * - Interface Segregation: Only audit logging
 * - Security: Tracks sensitive operations
 *
 * NOTE: This is a placeholder for Phase 4 implementation.
 */
public interface AuditLogPort {

    /**
     * Logs a successful user registration.
     *
     * @param userId the user ID
     * @param email the user email
     * @param ipAddress the client IP address
     */
    void logUserRegistered(String userId, String email, String ipAddress);

    /**
     * Logs a successful authentication.
     *
     * @param userId the user ID
     * @param email the user email
     * @param ipAddress the client IP address
     * @param userAgent the client User-Agent string
     */
    void logUserAuthenticated(String userId, String email, String ipAddress, String userAgent);

    /**
     * Logs a successful authentication with OAuth client information.
     *
     * @param userId the user ID
     * @param email the user email
     * @param ipAddress the client IP address
     * @param userAgent the client User-Agent string
     * @param oauthClientName the name of the OAuth client that initiated the login (e.g., "Marmara BYS")
     */
    void logUserAuthenticated(String userId, String email, String ipAddress, String userAgent, String oauthClientName);

    /**
     * Logs a failed authentication attempt.
     *
     * @param email the attempted email
     * @param ipAddress the client IP address
     * @param reason the failure reason
     */
    void logAuthenticationFailed(String email, String ipAddress, String reason);

    /**
     * Logs a user logout.
     *
     * @param userId the user ID
     * @param email the user email
     */
    void logUserLoggedOut(String userId, String email);

    /**
     * Logs a biometric enrollment.
     *
     * @param userId the user ID
     * @param success whether enrollment was successful
     */
    void logBiometricEnrollment(String userId, boolean success);

    /**
     * Logs a biometric verification attempt.
     *
     * @param userId the user ID
     * @param success whether verification was successful
     */
    void logBiometricVerification(String userId, boolean success);

    /**
     * Logs a generic security event.
     *
     * @param userId the user ID (or "UNKNOWN")
     * @param eventType the type of event (e.g., "PASSWORD_CHANGED")
     * @param ipAddress the client IP address
     * @param details additional event details
     */
    void logSecurityEvent(String userId, String eventType, String ipAddress, String details);
}
