package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for changing user password.
 *
 * Follows CQRS pattern - this is a write operation command.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordCommand {

    private String email;
    private String currentPassword;
    private String newPassword;
    private String ipAddress;
}
