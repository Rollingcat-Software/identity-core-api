package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;

/**
 * Input port for retrieving the current authenticated user.
 *
 * This interface defines the contract for getting user information
 * based on the authenticated email.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - get current user
 * - Dependency Inversion: Application defines the port
 * - CQRS: Query-only operation (no side effects)
 */
public interface GetCurrentUserUseCase {

    /**
     * Retrieves the current authenticated user by email.
     *
     * @param query the query containing user email
     * @return UserResponse with user data
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    UserResponse execute(GetUserByEmailQuery query);
}
