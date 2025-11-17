package com.fivucsas.identity.domain.exception;

/**
 * Thrown when biometric enrollment or verification fails.
 */
public class BiometricEnrollmentException extends DomainException {

    private static final String ERROR_CODE = "BIOMETRIC_ENROLLMENT_FAILED";

    public BiometricEnrollmentException(String message) {
        super(message, ERROR_CODE);
    }

    public BiometricEnrollmentException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
