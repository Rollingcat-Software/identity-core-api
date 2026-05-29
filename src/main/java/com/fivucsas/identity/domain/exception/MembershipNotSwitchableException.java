package com.fivucsas.identity.domain.exception;

/**
 * Thrown by the Phase-5 membership-switch flow when the caller is allowed to
 * assume the target membership (the same-identity HARD GATE passed) but the
 * target membership cannot currently be assumed — it is locked, suspended,
 * inactive, soft-deleted, or its tenant is not ACTIVE.
 *
 * <p>Mapped to HTTP 409 Conflict by {@code GlobalExceptionHandler}: the request
 * was well-formed and authorized for that account, but the target's current
 * state forbids the switch (a transient/stateful conflict, not an authz
 * failure). This is deliberately distinct from the same-identity gate, which is
 * a hard 403 ({@link MembershipSwitchForbiddenException}).</p>
 */
public class MembershipNotSwitchableException extends DomainException {

    private static final String ERROR_CODE = "MEMBERSHIP_NOT_SWITCHABLE";

    public MembershipNotSwitchableException(String message) {
        super(message, ERROR_CODE);
    }
}
