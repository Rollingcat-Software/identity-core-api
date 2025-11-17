package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a refresh token has expired.
 */
public class TokenExpiredException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Token has expired. Please login again.";
    private static final String ERROR_CODE = "TOKEN_EXPIRED";

    public TokenExpiredException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public TokenExpiredException(String tokenType) {
        super(String.format("%s token has expired. Please login again.", tokenType), ERROR_CODE);
    }

    public TokenExpiredException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
