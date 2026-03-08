package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for 2FA setup initiation.
 *
 * Contains secret and QR code URL for user to scan with authenticator app.
 *
 * Following principles:
 * - Data Transfer Object pattern
 * - Security: Secret should be shown only once
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TwoFactorSetupResponse {

    private String secret;  // Base64-encoded TOTP secret (show only once)
    private String qrCodeUrl;  // otpauth:// URL for QR code generation
    private String[] backupCodes;  // Backup codes for recovery (show only once)
    private String message;  // Instructions for user
}
