package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.ResetPasswordCommand;

/**
 * Input port for reset password use case.
 *
 * This interface defines the contract for resetting user password.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only reset password
 * - Dependency Inversion: Application defines the port
 */
public interface ResetPasswordUseCase {

    /**
     * Resets user password using reset token.
     *
     * @param command the command containing token and new password
     * @throws com.fivucsas.identity.domain.exception.InvalidTokenException if token is invalid or expired
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    void execute(ResetPasswordCommand command);
}
