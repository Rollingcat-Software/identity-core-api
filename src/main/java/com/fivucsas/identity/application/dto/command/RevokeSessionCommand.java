package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for revoking a specific session.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains session revocation data
 * - Command Pattern: Represents revoke session action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevokeSessionCommand {

    private String email;
    private String sessionId;  // RefreshToken ID
    private String ipAddress;
}
