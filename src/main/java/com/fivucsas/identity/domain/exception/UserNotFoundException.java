package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a requested user cannot be found.
 */
public class UserNotFoundException extends DomainException {

    private static final String DEFAULT_MESSAGE = "User not found";
    private static final String ERROR_CODE = "USER_NOT_FOUND";

    public UserNotFoundException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public UserNotFoundException(String identifier) {
        super(String.format("User not found: %s", identifier), ERROR_CODE);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
