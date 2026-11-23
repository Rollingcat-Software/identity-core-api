package com.fivucsas.identity.domain.exception;

/**
 * Thrown by the login path when it cannot decide whether a second factor is
 * required (issue #254).
 *
 * <p>{@link com.fivucsas.identity.application.service.AuthenticateUserService}
 * reads the tenant's default APP_LOGIN flow and the user's enrollment health to
 * decide between an MFA challenge and the single-factor token mint. When that
 * decision cannot be evaluated (repository failure, lazy-load failure, probe
 * failure), the historical code logged and continued, which minted a
 * single-factor JWT for a tenant that requires MFA: an authentication decision
 * that fails OPEN.</p>
 *
 * <p>This exception makes the decision fail CLOSED: no access or refresh token
 * is issued, and the request answers HTTP 503 so the client can retry once the
 * dependency recovers. The behaviour is reversible without a redeploy:
 * {@code app.auth.mfa-fail-closed=false} restores the legacy fail-open branch.</p>
 */
public class MfaDecisionUnavailableException extends DomainException {

    private static final String ERROR_CODE = "MFA_DECISION_UNAVAILABLE";

    public MfaDecisionUnavailableException(Throwable cause) {
        super("Login could not verify the tenant's multi-factor policy; no token was issued. Please retry shortly.",
                ERROR_CODE, cause);
    }
}