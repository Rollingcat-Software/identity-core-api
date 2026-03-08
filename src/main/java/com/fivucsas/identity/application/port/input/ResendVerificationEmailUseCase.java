package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.ResendVerificationEmailCommand;

/**
 * Input port for resending email verification.
 *
 * This interface defines the contract for resending verification emails.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only resend verification
 * - Dependency Inversion: Application defines the port
 */
public interface ResendVerificationEmailUseCase {

    /**
     * Resends verification email to user.
     *
     * @param command the command containing user email
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     * @throws com.fivucsas.identity.domain.exception.EmailAlreadyVerifiedException if email already verified
     */
    void execute(ResendVerificationEmailCommand command);
}
