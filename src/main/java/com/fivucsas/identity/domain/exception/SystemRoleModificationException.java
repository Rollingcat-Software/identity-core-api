package com.fivucsas.identity.domain.exception;

/**
 * Thrown when attempting to modify or delete a system role.
 * System roles are protected and cannot be changed.
 */
public class SystemRoleModificationException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Cannot modify system role";
    private static final String ERROR_CODE = "SYSTEM_ROLE_MODIFICATION";

    public SystemRoleModificationException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public SystemRoleModificationException(String message) {
        super(message, ERROR_CODE);
    }

    public SystemRoleModificationException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
