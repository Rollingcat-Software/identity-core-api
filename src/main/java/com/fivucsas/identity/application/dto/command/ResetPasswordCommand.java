package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for resetting password using reset token.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains password reset data
 * - Command Pattern: Represents reset password action
 * - Security: Password should be cleared after use
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordCommand {

    private String token;
    private String newPassword;
    private String ipAddress;
}
