package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for resending email verification link.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains user email
 * - Command Pattern: Represents resend verification email action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResendVerificationEmailCommand {

    private String email;
    private String ipAddress;
}
