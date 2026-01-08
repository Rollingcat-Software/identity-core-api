package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving users assigned to a role.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetRoleUsersQuery {

    private String roleId;
}
