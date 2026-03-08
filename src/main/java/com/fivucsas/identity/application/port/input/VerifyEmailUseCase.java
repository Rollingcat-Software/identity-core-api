package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.VerifyEmailCommand;

/**
 * Input port for email verification use case.
 *
 * This interface defines the contract for verifying user email addresses.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only email verification
 * - Dependency Inversion: Application defines the port
 */
public interface VerifyEmailUseCase {

    /**
     * Verifies a user's email address using a verification token.
     *
     * @param command the verification command containing token
     * @throws com.fivucsas.identity.domain.exception.InvalidTokenException if token is invalid or expired
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    void execute(VerifyEmailCommand command);
}
