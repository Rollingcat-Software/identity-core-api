package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;

/**
 * Input port for biometric enrollment use case.
 *
 * This interface defines the contract for enrolling users
 * in biometric authentication (face recognition).
 *
 * Following principles:
 * - Interface Segregation: Single responsibility - biometric enrollment
 * - Dependency Inversion: Application defines the port
 * - Security: Handles sensitive biometric data
 */
public interface EnrollBiometricUseCase {

    /**
     * Enrolls a user for biometric authentication.
     *
     * @param command the enrollment command containing user ID and biometric data
     * @return BiometricResponse with enrollment status and details
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     * @throws com.fivucsas.identity.domain.exception.BiometricEnrollmentException if enrollment fails
     */
    BiometricResponse execute(EnrollBiometricCommand command);
}
