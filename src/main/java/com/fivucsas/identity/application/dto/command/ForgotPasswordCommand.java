package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for initiating password reset flow.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains email for password reset
 * - Command Pattern: Represents forgot password action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ForgotPasswordCommand {

    private String email;
    private String ipAddress;
}
