package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;

/**
 * Input port for user authentication use case.
 *
 * This interface defines the contract for authenticating users with credentials.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only authentication
 * - Dependency Inversion: Application defines the port
 * - Security: Handles credentials securely
 */
public interface AuthenticateUserUseCase {

    /**
     * Authenticates a user with email and password.
     *
     * @param command the authentication command containing credentials
     * @return AuthenticationResponse with access token, refresh token, and user data
     * @throws com.fivucsas.identity.domain.exception.InvalidCredentialsException if credentials are invalid
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    AuthenticationResponse execute(AuthenticateUserCommand command);
}
