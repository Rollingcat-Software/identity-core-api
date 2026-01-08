package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Command for assigning a role to a user.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AssignRoleToUserCommand {

    private String userId;
    private String roleId;
    private String assignedBy;
    private Instant expiresAt;  // Optional expiration for time-limited roles
}
