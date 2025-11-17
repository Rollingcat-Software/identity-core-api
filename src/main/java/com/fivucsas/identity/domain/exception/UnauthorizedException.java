package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a user attempts to access a resource they don't have permission for.
 */
public class UnauthorizedException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Access denied";
    private static final String ERROR_CODE = "UNAUTHORIZED";

    public UnauthorizedException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public UnauthorizedException(String resource) {
        super(String.format("Access denied to resource: %s", resource), ERROR_CODE);
    }

    public UnauthorizedException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
