package com.fivucsas.identity.domain.exception;

/**
 * Thrown when attempting to register or update a user with an email that already exists.
 */
public class DuplicateEmailException extends DomainException {

    private static final String ERROR_CODE = "DUPLICATE_EMAIL";

    public DuplicateEmailException(String email) {
        super(String.format("Email already exists: %s", email), ERROR_CODE);
    }

    public DuplicateEmailException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
