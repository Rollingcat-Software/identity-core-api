package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving all users with pagination.
 *
 * Follows CQRS pattern - this is a read operation query.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetAllUsersQuery {

    @Builder.Default
    private int page = 0;

    @Builder.Default
    private int size = 20;
}
