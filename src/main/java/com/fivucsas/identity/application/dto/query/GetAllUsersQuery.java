package com.fivucsas.identity.application.dto.query;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving all users.
 *
 * Follows CQRS pattern - this is a read operation query.
 *
 * Following principles:
 * - Single Responsibility: Query marker (no criteria needed for "all")
 * - Query Pattern: Read-only operation (no side effects)
 *
 * NOTE: In production, this should support pagination.
 */
@Data
@Builder
@NoArgsConstructor
public class GetAllUsersQuery {

    // Placeholder for future pagination parameters
    // private Integer page;
    // private Integer size;
}
