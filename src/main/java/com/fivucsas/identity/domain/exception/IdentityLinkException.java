package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a Phase-2 account-link request violates a business rule that is
 * not a plain not-found / credential failure — e.g. the target membership is
 * inactive, the target lives in a tenant the caller already has a membership in
 * (would duplicate a membership), or an unlink target is not in the caller's
 * own identity.
 *
 * <p>Mapped to HTTP 422 Unprocessable Entity by {@code GlobalExceptionHandler}
 * (the request was well-formed but cannot be satisfied), mirroring the
 * onboarding domain-rule exceptions.</p>
 */
public class IdentityLinkException extends DomainException {

    private static final String ERROR_CODE = "IDENTITY_LINK_REJECTED";

    public IdentityLinkException(String message) {
        super(message, ERROR_CODE);
    }
}
