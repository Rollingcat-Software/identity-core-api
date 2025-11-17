package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for searching users by query string.
 *
 * Follows CQRS pattern - this is a read operation query.
 *
 * Following principles:
 * - Single Responsibility: Only contains search criteria
 * - Query Pattern: Read-only operation (no side effects)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SearchUsersQuery {

    private String searchQuery;
}
