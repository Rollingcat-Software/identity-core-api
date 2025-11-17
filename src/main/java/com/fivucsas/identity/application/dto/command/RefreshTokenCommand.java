package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for refreshing an access token.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains refresh token data
 * - Command Pattern: Represents token refresh action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenCommand {

    private String refreshToken;
    private String ipAddress;
    private String userAgent;
}
