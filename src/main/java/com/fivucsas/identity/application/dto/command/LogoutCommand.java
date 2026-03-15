package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for logging out a user.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains logout data
 * - Command Pattern: Represents logout action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogoutCommand {

    private String refreshToken;
    private String currentUserEmail;
    private String accessToken;
}
