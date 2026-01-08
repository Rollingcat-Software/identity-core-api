package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving all roles.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetAllRolesQuery {

    @Builder.Default
    private boolean includeInactive = false;

    @Builder.Default
    private boolean includeSystemRoles = true;
}
