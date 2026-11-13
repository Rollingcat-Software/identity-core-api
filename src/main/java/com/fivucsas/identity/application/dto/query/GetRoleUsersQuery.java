package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Query for retrieving users assigned to a role.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetRoleUsersQuery {

    private String roleId;

    /**
     * Tenant the result is limited to: only holders whose own tenant is this one are
     * returned. {@code null} means no restriction and is only set for ROOT.
     */
    private UUID tenantScope;
}
