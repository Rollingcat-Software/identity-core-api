package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a verification or reset token is invalid or expired.
 */
public class InvalidTokenException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Invalid or expired token";
    private static final String ERROR_CODE = "INVALID_TOKEN";

    public InvalidTokenException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public InvalidTokenException(String message) {
        super(message, ERROR_CODE);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
