package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.query.GetUserActivityLogQuery;
import com.fivucsas.identity.application.dto.response.ActivityLogResponse;
import org.springframework.data.domain.Page;

/**
 * Input port for getting user activity log use case.
 *
 * This interface defines the contract for retrieving user's activity history.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only get activity log
 * - Dependency Inversion: Application defines the port
 */
public interface GetUserActivityLogUseCase {

    /**
     * Retrieves activity log for a user with pagination.
     *
     * @param query the query containing user email and pagination
     * @return page of activity log entries
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    Page<ActivityLogResponse> execute(GetUserActivityLogQuery query);
}
