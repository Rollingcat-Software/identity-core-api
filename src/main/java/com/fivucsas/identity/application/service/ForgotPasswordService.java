package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ForgotPasswordCommand;
import com.fivucsas.identity.application.port.input.ForgotPasswordUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for forgot password.
 *
 * Implements the ForgotPasswordUseCase input port.
 * Generates password reset token and sends email.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ForgotPasswordService implements ForgotPasswordUseCase {

    private final UserRepository userRepository;
    private final EmailServicePort emailServicePort;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void execute(ForgotPasswordCommand command) {
        log.info("Password reset request for email: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + command.getEmail()));

        // Generate password reset token
        String resetToken = user.generatePasswordResetToken();
        userRepository.save(user);

        // Send password reset email
        emailServicePort.sendPasswordResetEmail(
            user.getEmail(),
            user.getFullName(),
            resetToken
        );

        log.info("Password reset email sent to: {}", command.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "PASSWORD_RESET_REQUESTED",
            command.getIpAddress(),
            "Password reset email sent"
        );
    }
}
