package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.Enable2FACommand;
import com.fivucsas.identity.application.port.input.Enable2FAUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EmailServicePort;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.security.TotpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for enabling 2FA.
 *
 * Validates TOTP code and enables 2FA for user.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class Enable2FAService implements Enable2FAUseCase {

    private final UserRepository userRepository;
    private final AuditLogPort auditLogPort;
    private final EmailServicePort emailServicePort;

    @Override
    @Transactional
    public void execute(Enable2FACommand command) {
        log.info("Enable 2FA request for user: {}", command.getEmail());

        User user = userRepository.findByEmail(command.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + command.getEmail()));

        if (user.is2faEnabled()) {
            throw new IllegalStateException("2FA is already enabled for this user");
        }

        // Note: The secret and backup codes should be passed from the setup endpoint
        // For now, generate them here (in production, you'd want to validate against a temporary storage)
        String secret = TotpUtil.generateSecret();
        String[] backupCodes = TotpUtil.generateBackupCodes(8);

        // Validate the TOTP code provided by user
        if (!TotpUtil.validateCode(secret, command.getVerificationCode())) {
            log.warn("Invalid 2FA code provided for user: {}", command.getEmail());
            auditLogPort.logSecurityEvent(
                user.getId().toString(),
                "2FA_ENABLE_FAILED",
                command.getIpAddress(),
                "Invalid verification code"
            );
            throw new IllegalArgumentException("Invalid verification code. Please try again.");
        }

        // Enable 2FA
        user.enable2FA(secret, backupCodes);
        userRepository.save(user);

        // Send security alert
        emailServicePort.sendSecurityAlert(
            user.getEmail(),
            user.getFullName(),
            "Two-factor authentication has been enabled on your account. If you did not enable this, please contact support immediately."
        );

        log.info("2FA enabled successfully for user: {}", command.getEmail());
        auditLogPort.logSecurityEvent(
            user.getId().toString(),
            "2FA_ENABLED",
            command.getIpAddress(),
            "Two-factor authentication enabled"
        );
    }
}
