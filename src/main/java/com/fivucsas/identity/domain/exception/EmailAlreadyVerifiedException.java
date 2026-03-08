package com.fivucsas.identity.domain.exception;

/**
 * Thrown when attempting to verify an email that is already verified.
 */
public class EmailAlreadyVerifiedException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Email address is already verified";
    private static final String ERROR_CODE = "EMAIL_ALREADY_VERIFIED";

    public EmailAlreadyVerifiedException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public EmailAlreadyVerifiedException(String message) {
        super(message, ERROR_CODE);
    }

    public EmailAlreadyVerifiedException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
