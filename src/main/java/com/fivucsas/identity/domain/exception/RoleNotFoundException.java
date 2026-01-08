package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a requested role cannot be found.
 */
public class RoleNotFoundException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Role not found";
    private static final String ERROR_CODE = "ROLE_NOT_FOUND";

    public RoleNotFoundException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public RoleNotFoundException(String identifier) {
        super(String.format("Role not found: %s", identifier), ERROR_CODE);
    }

    public RoleNotFoundException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
