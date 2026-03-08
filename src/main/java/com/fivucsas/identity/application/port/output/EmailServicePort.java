package com.fivucsas.identity.application.port.output;

/**
 * Output port for email operations.
 *
 * This interface defines the contract for sending transactional emails.
 * Implementation can use SMTP, SendGrid, AWS SES, or any other email service.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - email operations
 * - Dependency Inversion: Application defines contract, infrastructure implements
 * - Abstraction: Decouples from specific email provider
 */
public interface EmailServicePort {

    /**
     * Sends a welcome email after successful registration.
     *
     * @param toEmail recipient email address
     * @param name recipient name
     * @param verificationToken optional email verification token
     */
    void sendRegistrationEmail(String toEmail, String name, String verificationToken);

    /**
     * Sends a password reset email.
     *
     * @param toEmail recipient email address
     * @param name recipient name
     * @param resetToken password reset token
     */
    void sendPasswordResetEmail(String toEmail, String name, String resetToken);

    /**
     * Sends a security alert email.
     *
     * @param toEmail recipient email address
     * @param name recipient name
     * @param alertMessage the security alert message
     */
    void sendSecurityAlert(String toEmail, String name, String alertMessage);

    /**
     * Sends a two-factor authentication code.
     *
     * @param toEmail recipient email address
     * @param name recipient name
     * @param code the 2FA code
     */
    void send2FACode(String toEmail, String name, String code);

    /**
     * Sends a notification about biometric enrollment.
     *
     * @param toEmail recipient email address
     * @param name recipient name
     * @param success whether enrollment was successful
     */
    void sendBiometricEnrollmentNotification(String toEmail, String name, boolean success);

    /**
     * Sends account deactivation notification.
     *
     * @param toEmail recipient email address
     * @param name recipient name
     * @param reason reason for deactivation
     */
    void sendAccountDeactivationNotification(String toEmail, String name, String reason);
}
