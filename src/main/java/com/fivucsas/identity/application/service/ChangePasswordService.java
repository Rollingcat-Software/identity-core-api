package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ChangePasswordCommand;
import com.fivucsas.identity.application.port.input.ChangePasswordUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.user.PasswordPolicy;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for changing password.
 *
 * Validates current password and applies password policy.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ChangePasswordService implements ChangePasswordUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoderPort;
    private final PasswordEncoder passwordEncoder;  // For User.updatePassword()
    private final AuditLogPort auditLogPort;
    private final EmailServicePort emailServicePort;

    @Override
    @Transactional
    public void execute(ChangePasswordCommand command) {
        log.info("Change password request for user: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + command.getEmail()));

        // Verify current password
        if (!passwordEncoderPort.matches(command.getCurrentPassword(), user.getPasswordHash())) {
            log.warn("Invalid current password for change password attempt: {}", command.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "PASSWORD_CHANGE_FAILED",
                command.getIpAddress(),
                "Invalid current password"
            );
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        // Validate new password against policy
        PasswordPolicy.validate(command.getNewPassword());

        // Check if new password is same as current
        if (passwordEncoderPort.matches(command.getNewPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("New password must be different from current password");
        }

        // Update password (uses User entity method which applies policy)
        user.updatePassword(command.getNewPassword(), passwordEncoder);

        // Reset failed login attempts
        user.resetFailedLoginAttempts();

        userRepository.save(user);

        // Send security alert
        emailServicePort.sendSecurityAlert(
            user.getEmail(),
            user.getFullName(),
            "Your password has been changed successfully. If you did not make this change, please contact support immediately."
        );

        log.info("Password changed successfully for user: {}", command.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "PASSWORD_CHANGED",
            command.getIpAddress(),
            "Password changed successfully"
        );
    }
}
