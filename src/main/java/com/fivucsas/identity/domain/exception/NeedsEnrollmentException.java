package com.fivucsas.identity.domain.exception;

/**
 * Thrown when a user attempts to begin an authentication flow whose required
 * step references a method they have not enrolled, and no fallback is
 * configured. Post-audit 2026-04-24 login edge case #5.
 *
 * <p>The frontend catches this via the {@code NEEDS_ENROLLMENT} error code and
 * is expected to redirect the user to the enrollment URL carried on the
 * response body — avoiding the dead-end where the login session advances past
 * password only to trap the user mid-flow on an un-enrollable step.
 */
public class NeedsEnrollmentException extends DomainException {

    private static final String ERROR_CODE = "NEEDS_ENROLLMENT";

    private final String method;
    private final String enrollmentUrl;

    public NeedsEnrollmentException(String method, String enrollmentUrl) {
        super(
                "This login flow requires " + method + " but you have not enrolled it yet.",
                ERROR_CODE
        );
        this.method = method;
        this.enrollmentUrl = enrollmentUrl;
    }

    public String getMethod() {
        return method;
    }

    public String getEnrollmentUrl() {
        return enrollmentUrl;
    }
}
