package com.fivucsas.identity.domain.exception;

/**
 * Thrown by the Phase-5 membership-switch flow when the caller attempts to
 * assume a membership that does NOT belong to their own platform identity — the
 * HARD GATE in {@code SwitchMembershipService}.
 *
 * <p>This is the ONLY barrier between accounts, so it is mapped to a strict HTTP
 * 403 Forbidden by {@code GlobalExceptionHandler}. It is raised when the
 * target's {@code identity_id} is {@code null} or differs from the caller's
 * {@code identity_id}. The message is intentionally generic (no enumeration of
 * whether the target exists) so it cannot be used to probe foreign memberships.</p>
 */
public class MembershipSwitchForbiddenException extends DomainException {

    private static final String DEFAULT_MESSAGE =
            "You may only switch to a membership that belongs to your own identity";
    private static final String ERROR_CODE = "MEMBERSHIP_SWITCH_FORBIDDEN";

    public MembershipSwitchForbiddenException() {
        super(DEFAULT_MESSAGE, ERROR_CODE);
    }

    public MembershipSwitchForbiddenException(String message) {
        super(message, ERROR_CODE);
    }
}
