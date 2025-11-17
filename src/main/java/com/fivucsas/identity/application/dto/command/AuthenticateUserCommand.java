package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for authenticating a user.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains authentication credentials
 * - Command Pattern: Represents authentication action
 * - Security: Sensitive data (password) should be cleared after use
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticateUserCommand {

    private String email;
    private String password;
    private String ipAddress;
    private String userAgent;
}
