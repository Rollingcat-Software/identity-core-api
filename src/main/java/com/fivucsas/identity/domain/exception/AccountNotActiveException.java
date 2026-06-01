package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a login attempt is made against an account whose status is not
 * ACTIVE (SUSPENDED or INACTIVE/DEACTIVATED). Maps to HTTP 403.
 *
 * <p>Distinct from {@link AccountLockedException} (a temporary brute-force
 * lockout, HTTP 423): a non-active account is a deliberate administrative state,
 * not a transient lock, and never auto-clears.
 */
public class AccountNotActiveException extends DomainException {

    private static final String DEFAULT_MESSAGE =
            "This account is not active. Please contact your administrator.";
    private static final String ERROR_CODE = "ACCOUNT_NOT_ACTIVE";

    public AccountNotActiveException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public AccountNotActiveException(String message) {
        super(message, ERROR_CODE);
    }
}
