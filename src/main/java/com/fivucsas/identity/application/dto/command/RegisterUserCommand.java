package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for registering a new user.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains data for user registration
 * - Immutability: Use with @Builder for safer construction
 * - Command Pattern: Represents a specific action (register user)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterUserCommand {

    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private String ipAddress;
    private String userAgent;
}
