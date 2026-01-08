package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving a role by ID.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetRoleByIdQuery {

    private String roleId;
}
