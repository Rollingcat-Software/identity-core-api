package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a requested permission cannot be found.
 */
public class PermissionNotFoundException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Permission not found";
    private static final String ERROR_CODE = "PERMISSION_NOT_FOUND";

    public PermissionNotFoundException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public PermissionNotFoundException(String identifier) {
        super(String.format("Permission not found: %s", identifier), ERROR_CODE);
    }

    public PermissionNotFoundException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
