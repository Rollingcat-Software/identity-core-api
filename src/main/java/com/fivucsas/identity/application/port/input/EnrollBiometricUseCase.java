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

    /**
     * Marks a user as biometric-enrolled (sets {@code is_biometric_enrolled} +
     * {@code enrolled_at}). The single-image {@link #execute} path does this for FACE
     * enrollment; the multi-image enroll path ({@code POST /biometric/enroll/multi})
     * goes straight through {@code BiometricServicePort} and historically did NOT —
     * so {@code /biometric/verify} (which gates on the flag) rejected multi-enrolled
     * users with 412 "not enrolled" despite a stored embedding. The controller calls
     * this on a successful multi-enroll. Idempotent (no-op if already enrolled).
     *
     * @param userId the user to mark enrolled
     * @throws com.fivucsas.identity.domain.exception.UserNotFoundException if user doesn't exist
     */
    void markBiometricEnrolled(java.util.UUID userId);
}
