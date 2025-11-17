package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;

/**
 * Input port for biometric verification use case.
 *
 * This interface defines the contract for verifying users
 * using biometric authentication (face recognition).
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - biometric verification
 * - Dependency Inversion: Application defines the port
 * - Security: Validates biometric data
 */
public interface VerifyBiometricUseCase {

    /**
     * Verifies a user using biometric authentication.
     *
     * @param command the verification command containing user ID and biometric data
     * @return BiometricResponse with verification result
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     * @throws com.fivucsas.identity.domain.exception.BiometricNotEnrolledException if user not enrolled
     * @throws com.fivucsas.identity.domain.exception.BiometricVerificationException if verification fails
     */
    BiometricResponse execute(VerifyBiometricCommand command);
}
