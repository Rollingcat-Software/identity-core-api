package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for revoking a role from a user.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevokeRoleFromUserCommand {

    private String userId;
    private String roleId;
}
