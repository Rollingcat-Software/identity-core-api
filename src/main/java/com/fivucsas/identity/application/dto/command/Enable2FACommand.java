package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for enabling two-factor authentication.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains 2FA enablement data
 * - Command Pattern: Represents enable 2FA action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Enable2FACommand {

    private String email;
    private String verificationCode;  // Code from authenticator app to confirm setup
    private String ipAddress;
}
