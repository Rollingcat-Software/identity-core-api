package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.LogoutCommand;

/**
 * Input port for user logout use case.
 *
 * This interface defines the contract for logging out users and
 * revoking their refresh tokens.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only logout
 * - Dependency Inversion: Application defines the port
 * - Security: Properly revokes tokens
 */
public interface LogoutUserUseCase {

    /**
     * Logs out a user and revokes their refresh token.
     *
     * @param command the logout command containing refresh token
     * @throws com.fivucsas.identity.domain.exception.TokenRevokedException if token already revoked
     */
    void execute(LogoutCommand command);
}
