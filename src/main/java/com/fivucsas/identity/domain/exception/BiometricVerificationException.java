package com.fivucsas.identity.domain.exception;

/**
 * Thrown when biometric verification fails.
 */
public class BiometricVerificationException extends DomainException {

    private static final String ERROR_CODE = "BIOMETRIC_VERIFICATION_FAILED";

    public BiometricVerificationException(String message) {
        super(message, ERROR_CODE);
    }

    public BiometricVerificationException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
