package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RevokeAllSessionsCommand;

/**
 * Input port for revoking all sessions except current one.
 *
 * This interface defines the contract for revoking all user sessions.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only revoke all sessions
 * - Dependency Inversion: Application defines the port
 */
public interface RevokeAllSessionsUseCase {

    /**
     * Revokes all user sessions except the current one.
     *
     * @param command the command containing user email and current token
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    void execute(RevokeAllSessionsCommand command);
}
