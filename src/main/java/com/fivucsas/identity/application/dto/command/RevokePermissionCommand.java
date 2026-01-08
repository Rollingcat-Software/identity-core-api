package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for revoking a permission from a role.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevokePermissionCommand {

    private String roleId;
    private String permissionId;
}
