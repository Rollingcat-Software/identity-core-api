package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a sensitive biometric operation requires biometric step-up.
 */
public class BiometricStepUpRequiredException extends DomainException {

    private static final String ERROR_CODE = "STEP_UP_REQUIRED";

    public BiometricStepUpRequiredException() {
        super("Biometric step-up is required for this operation.", ERROR_CODE);
    }

    public BiometricStepUpRequiredException(String message) {
        super(message, ERROR_CODE);
    }
}
