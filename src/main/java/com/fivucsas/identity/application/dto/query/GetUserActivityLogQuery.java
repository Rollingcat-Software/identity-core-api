package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving user's activity log.
 *
 * Follows CQRS pattern - this is a read operation query.
 *
 * Following principles:
 * - Single Responsibility: Only contains user email for activity lookup
 * - Query Pattern: Represents read operation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetUserActivityLogQuery {

    private String email;
    private int page;
    private int size;
}
