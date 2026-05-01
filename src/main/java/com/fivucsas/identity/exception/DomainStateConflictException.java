package com.fivucsas.identity.exception;

/**
 * Domain-level "state conflict" — e.g. invitation already exists, attempt to
 * accept an expired invite, retry a non-failed enrollment, completing an
 * already-terminal verification session, etc.
 *
 * <p>Maps to HTTP 409 via {@link GlobalExceptionHandler}. Introduced in
 * Copilot post-merge round 5: previously {@link IllegalStateException} was
 * caught generically and forced to 409, which silently demoted internal
 * faults (crypto/key loading, missing JWT claims, tenant context errors) from
 * 500 to a misleading client-conflict.</p>
 */
public class DomainStateConflictException extends RuntimeException {

    public DomainStateConflictException(String message) {
        super(message);
    }

    public DomainStateConflictException(String message, Throwable cause) {
        super(message, cause);
    }
}
