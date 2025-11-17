package com.fivucsas.identity.domain.exception;

/**
 * Thrown when authentication fails due to invalid credentials.
 * Message is intentionally generic to prevent username enumeration attacks.
 */
public class InvalidCredentialsException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Invalid email or password";
    private static final String ERROR_CODE = "INVALID_CREDENTIALS";

    public InvalidCredentialsException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public InvalidCredentialsException(String message) {
        super(message, ERROR_CODE);
    }

    public InvalidCredentialsException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
