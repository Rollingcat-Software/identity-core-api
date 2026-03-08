package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.ForgotPasswordCommand;

/**
 * Input port for forgot password use case.
 *
 * This interface defines the contract for initiating password reset flow.
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - only forgot password
 * - Dependency Inversion: Application defines the port
 */
public interface ForgotPasswordUseCase {

    /**
     * Initiates password reset flow by sending reset email.
     *
     * @param command the command containing user email
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    void execute(ForgotPasswordCommand command);
}
