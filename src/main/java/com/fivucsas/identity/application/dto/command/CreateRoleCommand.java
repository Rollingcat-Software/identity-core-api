package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Command for creating a new role.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateRoleCommand {

    private String tenantId;
    private String name;
    private String description;
    private boolean systemRole;
    private List<String> permissionIds;
}
