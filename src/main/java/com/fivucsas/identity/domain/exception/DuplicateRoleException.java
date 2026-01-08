package com.fivucsas.identity.domain.exception;

/**
 * Thrown when attempting to create a role that already exists.
 */
public class DuplicateRoleException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Role already exists";
    private static final String ERROR_CODE = "DUPLICATE_ROLE";

    public DuplicateRoleException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public DuplicateRoleException(String roleName) {
        super(String.format("Role already exists: %s", roleName), ERROR_CODE);
    }

    public DuplicateRoleException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
