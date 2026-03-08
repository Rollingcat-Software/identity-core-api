package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for disabling two-factor authentication.
 *
 * Follows CQRS pattern - this is a write operation command.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Disable2FACommand {

    private String email;
    private String password;  // Require password confirmation
    private String ipAddress;
}
