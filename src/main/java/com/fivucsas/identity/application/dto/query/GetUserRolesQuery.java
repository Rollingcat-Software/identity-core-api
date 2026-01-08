package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving roles assigned to a user.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetUserRolesQuery {

    private String userId;
}
