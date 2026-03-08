package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for verifying a user's email address.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains email verification data
 * - Command Pattern: Represents email verification action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyEmailCommand {

    private String token;
    private String ipAddress;
}
