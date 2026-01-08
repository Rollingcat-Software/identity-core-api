package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Command for updating an existing role.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateRoleCommand {

    private String roleId;
    private String name;
    private String description;
    private Boolean active;
}
