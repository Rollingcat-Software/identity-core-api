package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.EmailServicePort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * No-op adapter implementing EmailServicePort.
 * Active when mail.enabled=false (default).
 *
 * Logs all email operations without actually sending emails.
 * Used in development and testing environments.
 */
@Service
@ConditionalOnProperty(name = "mail.enabled", havingValue = "false", matchIfMissing = true)
@Slf4j
public class EmailServiceAdapter implements EmailServicePort {

    @Override
    public void sendRegistrationEmail(String toEmail, String name, String verificationToken) {
        log.info("[MAIL DISABLED] Registration email to {}: verification token = {}", toEmail, verificationToken);
    }

    @Override
    public void sendPasswordResetEmail(String toEmail, String name, String resetToken) {
        log.info("[MAIL DISABLED] Password reset email to {}: reset token = {}", toEmail, resetToken);
    }

    @Override
    public void sendSecurityAlert(String toEmail, String name, String alertMessage) {
        log.info("[MAIL DISABLED] Security alert email to {}: {}", toEmail, alertMessage);
    }

    @Override
    public void send2FACode(String toEmail, String name, String code) {
        log.info("[MAIL DISABLED] 2FA code email to {}: code = {}", toEmail, code);
    }

    @Override
    public void sendBiometricEnrollmentNotification(String toEmail, String name, boolean success) {
        log.info("[MAIL DISABLED] Biometric enrollment notification to {}: success = {}", toEmail, success);
    }

    @Override
    public void sendAccountDeactivationNotification(String toEmail, String name, String reason) {
        log.info("[MAIL DISABLED] Account deactivation notification to {}: reason = {}", toEmail, reason);
    }
}
