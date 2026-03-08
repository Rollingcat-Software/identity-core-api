package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RevokeSessionCommand;

/**
 * Input port for revoking a session use case.
 *
 * This interface defines the contract for revoking a specific user session.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only revoke session
 * - Dependency Inversion: Application defines the port
 */
public interface RevokeSessionUseCase {

    /**
     * Revokes a specific user session.
     *
     * @param command the command containing session ID
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     * @throws com.fivucsas.identity.domain.exception.ResourceNotFoundException if session doesn't exist
     */
    void execute(RevokeSessionCommand command);
}
