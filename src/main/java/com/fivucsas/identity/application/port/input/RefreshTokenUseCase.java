package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RefreshTokenCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;

/**
 * Input port for refreshing access tokens.
 *
 * This interface defines the contract for refreshing expired access tokens
 * using valid refresh tokens.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only token refresh
 * - Dependency Inversion: Application defines the port
 * - Security: Validates refresh tokens
 */
public interface RefreshTokenUseCase {

    /**
     * Refreshes an access token using a refresh token.
     *
     * @param command the refresh token command
     * @return AuthenticationResponse with new access token and same refresh token
     * @throws com.fivucsas.identity.domain.exception.TokenExpiredException if refresh token is expired
     * @throws com.fivucsas.identity.domain.exception.TokenRevokedException if refresh token is revoked
     */
    AuthenticationResponse execute(RefreshTokenCommand command);
}
