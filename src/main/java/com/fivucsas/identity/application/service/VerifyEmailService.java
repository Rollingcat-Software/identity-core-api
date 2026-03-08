package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.VerifyEmailCommand;
import com.fivucsas.identity.application.port.input.VerifyEmailUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.InvalidTokenException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for email verification.
 *
 * Implements the VerifyEmailUseCase input port.
 * Logs all verification attempts to audit log.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class VerifyEmailService implements VerifyEmailUseCase {

    private final UserRepository userRepository;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void execute(VerifyEmailCommand command) {
        log.info("Email verification attempt with token: {}", command.getToken());

        // Find user by verification token
        User user = userRepository.findByEmailVerificationToken(command.getToken())
            .orElseThrow(() -> {
                auditLogPort.logSecurityEvent(
                    "UNKNOWN",
                    "EMAIL_VERIFICATION_FAILED",
                    command.getIpAddress(),
                    "Invalid verification token"
                );
                return new InvalidTokenException("Invalid or expired verification token");
            });

        // Check if already verified
        if (user.isEmailVerified()) {
            log.info("Email already verified for user: {}", user.getEmail());
            return;
        }

        // Check if token is expired
        if (user.isVerificationTokenExpired()) {
            log.warn("Verification token expired for user: {}", user.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "EMAIL_VERIFICATION_FAILED",
                command.getIpAddress(),
                "Token expired"
            );
            throw new InvalidTokenException("Verification token has expired. Please request a new one.");
        }

        // Verify email
        boolean success = user.verifyEmail(command.getToken());
        if (!success) {
            log.error("Email verification failed for user: {}", user.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "EMAIL_VERIFICATION_FAILED",
                command.getIpAddress(),
                "Token mismatch"
            );
            throw new InvalidTokenException("Failed to verify email");
        }

        userRepository.save(user);

        log.info("Email verified successfully for user: {}", user.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "EMAIL_VERIFIED",
            command.getIpAddress(),
            "Email verification successful"
        );
    }
}
