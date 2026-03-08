package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.query.GetActiveSessionsQuery;
import com.fivucsas.identity.application.dto.response.SessionResponse;

import java.util.List;

/**
 * Input port for getting active sessions use case.
 *
 * This interface defines the contract for retrieving user's active sessions.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only get sessions
 * - Dependency Inversion: Application defines the port
 */
public interface GetActiveSessionsUseCase {

    /**
     * Retrieves all active sessions for a user.
     *
     * @param query the query containing user email
     * @return list of active sessions
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    List<SessionResponse> execute(GetActiveSessionsQuery query);
}
