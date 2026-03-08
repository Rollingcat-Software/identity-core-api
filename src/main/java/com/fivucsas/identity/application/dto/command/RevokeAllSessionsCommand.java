package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for revoking all sessions except current one.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains user email and current token
 * - Command Pattern: Represents revoke all sessions action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevokeAllSessionsCommand {

    private String email;
    private String currentTokenId;  // Keep this session active
    private String ipAddress;
}
