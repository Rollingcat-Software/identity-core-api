package com.fivucsas.identity.domain.exception;

/**
 * Thrown when attempting to use a revoked token.
 */
public class TokenRevokedException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Token has been revoked. Please login again.";
    private static final String ERROR_CODE = "TOKEN_REVOKED";

    public TokenRevokedException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public TokenRevokedException(String message) {
        super(message, ERROR_CODE);
    }

    public TokenRevokedException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
