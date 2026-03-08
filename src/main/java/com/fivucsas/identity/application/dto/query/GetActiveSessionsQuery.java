package com.fivucsas.identity.application.dto.query;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Query for retrieving active sessions for a user.
 *
 * Follows CQRS pattern - this is a read operation query.
 *
 * Following principles:
 * - Single Responsibility: Only contains user email for session lookup
 * - Query Pattern: Represents read operation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GetActiveSessionsQuery {

    private String email;
    private String currentTokenId;  // To mark current session
}
