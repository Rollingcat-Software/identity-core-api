package com.fivucsas.identity.infrastructure.email;

import com.fivucsas.identity.application.port.output.EmailServicePort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Adapter that implements the EmailServicePort output port.
 *
 * Delegates to the existing EmailService infrastructure for actual sending.
 * Methods that are not supported by the underlying EmailService are logged
 * as no-ops until a full email provider (e.g. SendGrid, AWS SES) is integrated.
 */
@Component
@ConditionalOnProperty(name = "mail.enabled", havingValue = "true")
@RequiredArgsConstructor
@Slf4j
public class EmailServicePortAdapter implements EmailServicePort {

    private final EmailService emailService;

    @Override
    public void sendRegistrationEmail(String toEmail, String name, String verificationToken) {
        log.info("Sending registration email to domain: {}", maskEmail(toEmail));
        emailService.sendOtp(toEmail, verificationToken);
    }

    @Override
    public void sendPasswordResetEmail(String toEmail, String name, String resetToken) {
        log.info("Sending password reset email to domain: {}", maskEmail(toEmail));
        emailService.sendOtp(toEmail, resetToken);
    }

    @Override
    public void sendSecurityAlert(String toEmail, String name, String alertMessage) {
        log.info("Security alert for domain {}: {}", maskEmail(toEmail), alertMessage);
    }

    @Override
    public void send2FACode(String toEmail, String name, String code) {
        log.info("Sending 2FA code to domain: {}", maskEmail(toEmail));
        emailService.sendOtp(toEmail, code);
    }

    @Override
    public void sendBiometricEnrollmentNotification(String toEmail, String name, boolean success) {
        log.info("Biometric enrollment notification for domain {}: success={}", maskEmail(toEmail), success);
    }

    @Override
    public void sendAccountDeactivationNotification(String toEmail, String name, String reason) {
        log.info("Account deactivation notification for domain {}: reason={}", maskEmail(toEmail), reason);
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        return "***@" + email.substring(email.indexOf('@') + 1);
    }
}
