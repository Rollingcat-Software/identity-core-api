package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving roles by tenant.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetRolesByTenantQuery {

    private String tenantId;
}
