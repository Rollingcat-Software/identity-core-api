package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ResetPasswordCommand;
import com.fivucsas.identity.application.port.input.ResetPasswordUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.InvalidTokenException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for resetting password.
 *
 * Implements the ResetPasswordUseCase input port.
 * Validates reset token and updates password.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ResetPasswordService implements ResetPasswordUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final EmailServicePort emailServicePort;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void execute(ResetPasswordCommand command) {
        log.info("Password reset attempt with token");

        // Find user by reset token
        User user = userRepository.findByPasswordResetToken(command.getToken())
            .orElseThrow(() -> {
                auditLogPort.logSecurityEvent(
                    "UNKNOWN",
                    "PASSWORD_RESET_FAILED",
                    command.getIpAddress(),
                    "Invalid reset token"
                );
                return new InvalidTokenException("Invalid or expired reset token");
            });

        // Check if token is expired
        if (user.isPasswordResetTokenExpired()) {
            log.warn("Reset token expired for user: {}", user.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "PASSWORD_RESET_FAILED",
                command.getIpAddress(),
                "Token expired"
            );
            throw new InvalidTokenException("Reset token has expired. Please request a new one.");
        }

        // Validate new password against policy
        com.fivucsas.identity.domain.model.user.PasswordPolicy.validate(command.getNewPassword());

        // Hash new password
        String hashedPassword = passwordEncoder.encode(command.getNewPassword());

        // Reset password
        boolean success = user.resetPassword(command.getToken(), hashedPassword);
        if (!success) {
            log.error("Password reset failed for user: {}", user.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "PASSWORD_RESET_FAILED",
                command.getIpAddress(),
                "Token validation failed"
            );
            throw new InvalidTokenException("Failed to reset password");
        }

        // Reset failed login attempts (account might have been locked)
        user.resetFailedLoginAttempts();

        userRepository.save(user);

        // Send security alert email
        emailServicePort.sendSecurityAlert(
            user.getEmail(),
            user.getFullName(),
            "Your password has been successfully reset. If you did not perform this action, please contact support immediately."
        );

        log.info("Password reset successfully for user: {}", user.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "PASSWORD_RESET_SUCCESS",
            command.getIpAddress(),
            "Password reset successful"
        );
    }
}
