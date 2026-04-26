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

    /**
     * Logs an MFA step completion.
     *
     * @param userId the user ID
     * @param method the auth method used (e.g., "SMS_OTP", "FACE")
     * @param stepCurrent current step number
     * @param stepTotal total number of steps
     * @param ipAddress the client IP address
     * @param userAgent the client User-Agent string
     */
    void logMfaStepCompleted(String userId, String method, int stepCurrent, int stepTotal,
                             String ipAddress, String userAgent);

    /**
     * Logs a failed MFA step attempt.
     *
     * @param userId the user ID
     * @param method the auth method attempted (e.g., "FACE", "TOTP")
     * @param reason failure reason (e.g., "low_confidence", "invalid_otp")
     * @param ipAddress the client IP address
     * @param userAgent the client User-Agent string
     */
    void logMfaStepFailed(String userId, String method, String reason,
                          String ipAddress, String userAgent);

    /**
     * Logs successful completion of all MFA steps (full authentication).
     *
     * @param userId the user ID
     * @param amrValues the RFC 8176 amr claim values (e.g., ["pwd", "sms"])
     * @param ipAddress the client IP address
     * @param userAgent the client User-Agent string
     */
    void logMfaComplete(String userId, java.util.List<String> amrValues,
                        String ipAddress, String userAgent);

    /**
     * Logs a failed 2FA verification attempt (legacy 2FA endpoints).
     *
     * @param userId the user ID
     * @param method the auth method attempted
     * @param reason failure reason
     * @param ipAddress the client IP address
     * @param userAgent the client User-Agent string
     */
    void logTwoFactorFailed(String userId, String method, String reason,
                            String ipAddress, String userAgent);

    /**
     * Logs a successful 2FA verification (legacy 2FA endpoints).
     *
     * @param userId the user ID
     * @param method the auth method used
     * @param ipAddress the client IP address
     * @param userAgent the client User-Agent string
     */
    void logTwoFactorVerified(String userId, String method,
                              String ipAddress, String userAgent);

    /**
     * Logs an OAuth2 PKCE / authorization-code verification failure at the
     * token endpoint (Phase D5a).
     *
     * <p>Recorded for every {@code code_verifier} mismatch, missing verifier,
     * code reuse, or expired/unknown authorization code. The audit row never
     * carries the verifier or challenge — those are the secret being attacked.
     * It carries the {@code clientId} (so SOC can trace which integration is
     * under attack), the actor IP (network-level attribution), and a
     * {@code failureReason} string drawn from {@link com.fivucsas.identity.domain.model.PkceFailureReason}.</p>
     *
     * <p>The action stamped on the audit row is
     * {@link com.fivucsas.identity.domain.model.AuditAction#PKCE_FAILURE}.</p>
     *
     * @param clientId the OAuth2 client_id present in the failed token request
     * @param actorIp  the client IP that made the token request
     * @param failureReason categorisation drawn from {@code PkceFailureReason.name()}
     */
    void logPkceFailure(String clientId, String actorIp, String failureReason);
}
