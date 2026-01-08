package com.fivucsas.identity.domain.exception;

/**
 * Thrown when attempting to assign a role that is already assigned to a user.
 */
public class DuplicateRoleAssignmentException extends DomainException {

    private static final String DEFAULT_MESSAGE = "Role already assigned to user";
    private static final String ERROR_CODE = "DUPLICATE_ROLE_ASSIGNMENT";

    public DuplicateRoleAssignmentException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public DuplicateRoleAssignmentException(String userId, String roleId) {
        super(String.format("User %s already has role %s", userId, roleId), ERROR_CODE);
    }

    public DuplicateRoleAssignmentException(String message, Throwable cause) {
        super(message, ERROR_CODE, cause);
    }
}
