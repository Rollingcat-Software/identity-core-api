package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.Disable2FACommand;
import com.fivucsas.identity.application.port.input.Disable2FAUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for disabling 2FA.
 *
 * Requires password verification for security.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class Disable2FAService implements Disable2FAUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final AuditLogPort auditLogPort;
    private final EmailServicePort emailServicePort;

    @Override
    @Transactional
    public void execute(Disable2FACommand command) {
        log.info("Disable 2FA request for user: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + command.getEmail()));

        if (!user.is2faEnabled()) {
            throw new IllegalStateException("2FA is not enabled for this user");
        }

        // Verify password for security
        if (!passwordEncoder.matches(command.getPassword(), user.getPasswordHash())) {
            log.warn("Invalid password for 2FA disable attempt: {}", command.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "2FA_DISABLE_FAILED",
                command.getIpAddress(),
                "Invalid password"
            );
            throw new InvalidCredentialsException("Invalid password");
        }

        // Disable 2FA
        user.disable2FA();
        userRepository.save(user);

        // Send security alert
        emailServicePort.sendSecurityAlert(
            user.getEmail(),
            user.getFullName(),
            "Two-factor authentication has been disabled on your account. If you did not disable this, please contact support and change your password immediately."
        );

        log.info("2FA disabled successfully for user: {}", command.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "2FA_DISABLED",
            command.getIpAddress(),
            "Two-factor authentication disabled"
        );
    }
}
