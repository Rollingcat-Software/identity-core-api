package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving a permission by ID.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetPermissionByIdQuery {

    private String permissionId;
}
