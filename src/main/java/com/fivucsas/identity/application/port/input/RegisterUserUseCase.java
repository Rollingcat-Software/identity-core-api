package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;

/**
 * Input port for user registration use case.
 *
 * This interface defines the contract for registering new users.
 * Follows the Dependency Inversion Principle - the application layer
 * defines what it needs, and the adapter layer provides implementations.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only user registration
 * - Dependency Inversion: Application defines the port, infrastructure implements it
 * - Open/Closed: Can add new implementations without changing the interface
 */
public interface RegisterUserUseCase {

    /**
     * Registers a new user in the system.
     *
     * @param command the registration command containing user details
     * @return AuthenticationResponse with access token, refresh token, and user data
     * @throws com.fivucsas.identity.domain.exception.DuplicateEmailException if email already exists
     * @throws IllegalArgumentException if command contains invalid data
     */
    AuthenticationResponse execute(RegisterUserCommand command);
}
