package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.ResendVerificationEmailCommand;
import com.fivucsas.identity.application.port.input.ResendVerificationEmailUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.domain.exception.EmailAlreadyVerifiedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for resending verification email.
 *
 * Implements the ResendVerificationEmailUseCase input port.
 * Generates new verification token and sends email.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ResendVerificationEmailService implements ResendVerificationEmailUseCase {

    private final UserRepository userRepository;
    private final EmailServicePort emailServicePort;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void execute(ResendVerificationEmailCommand command) {
        log.info("Resend verification email request for: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + command.getEmail()));

        // Check if already verified
        if (user.isEmailVerified()) {
            log.info("Email already verified for user: {}", command.getEmail());
            throw new EmailAlreadyVerifiedException();
        }

        // Generate new verification token
        String verificationToken = user.generateEmailVerificationToken();
        userRepository.save(user);

        // Send verification email
        emailServicePort.sendRegistrationEmail(
            user.getEmail(),
            user.getFullName(),
            verificationToken
        );

        log.info("Verification email resent to: {}", command.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "VERIFICATION_EMAIL_RESENT",
            command.getIpAddress(),
            "Verification email resent"
        );
    }
}
