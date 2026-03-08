package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.TwoFactorSetupResponse;
import com.fivucsas.identity.application.port.input.Setup2FAUseCase;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.security.TotpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for setting up 2FA.
 *
 * Generates TOTP secret, QR code URL, and backup codes for user.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class Setup2FAService implements Setup2FAUseCase {

    private final UserRepository userRepository;

    @Value("${app.name:FIVUCSAS Identity}")
    private String appName;

    @Override
    @Transactional(readOnly = true)
    public TwoFactorSetupResponse execute(GetUserByEmailQuery query) {
        log.info("2FA setup initiated for user: {}", query.getEmail());

        User user = userRepository.findByEmail(query.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + query.getEmail()));

        // Generate new TOTP secret
        String secret = TotpUtil.generateSecret();

        // Generate QR code URL for authenticator apps
        String qrCodeUrl = TotpUtil.generateQrCodeUrl(user.getEmail(), secret, appName);

        // Generate backup codes
        String[] backupCodes = TotpUtil.generateBackupCodes(8);

        log.info("2FA setup generated for user: {}", query.getEmail());

        return TwoFactorSetupResponse.builder()
            .secret(secret)
            .qrCodeUrl(qrCodeUrl)
            .backupCodes(backupCodes)
            .message("Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.) and enter the 6-digit code to complete setup. Save your backup codes in a secure location.")
            .build();
    }
}
