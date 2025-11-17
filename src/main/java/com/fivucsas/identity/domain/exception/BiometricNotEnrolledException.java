package com.fivucsas.identity.domain.exception;

/**
 * Thrown when attempting biometric verification for a user who hasn't enrolled biometrics.
 */
public class BiometricNotEnrolledException extends DomainException {

    private static final String DEFAULT_MESSAGE = "User has not enrolled biometric data";
    private static final String ERROR_CODE = "BIOMETRIC_NOT_ENROLLED";

    public BiometricNotEnrolledException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public BiometricNotEnrolledException(String userId) {
        super(String.format("User %s has not enrolled biometric data", userId), ERROR_CODE);
    }

    public BiometricNotEnrolledException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
