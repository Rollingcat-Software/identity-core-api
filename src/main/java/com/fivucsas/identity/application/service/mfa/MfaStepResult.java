package com.fivucsas.identity.application.service.mfa;

/**
 * Outcome of a single MFA step verification handler invocation.
 *
 * <p>The handler is responsible only for the per-method correctness check
 * (e.g. did this OTP code validate? did this WebAuthn assertion verify?).
 * Cross-cutting concerns — same-method reuse guards, audit logging,
 * MFA session step advancement, JWT minting, RFC 8176 {@code amr}
 * accumulation — remain in {@link VerifyMfaStepService}.
 *
 * <p>{@code valid=true} means the per-method check passed. {@code valid=false}
 * is non-fatal: the orchestrator turns it into a {@code status=FAILED} HTTP
 * response so the user can retry the same step.
 *
 * <p>{@code challenge}-style intermediate responses (WebAuthn challenge
 * generation) are signalled via {@link #challengeResponse()} — the orchestrator
 * short-circuits and returns it as-is without advancing the session.
 */
public record MfaStepResult(
        boolean valid,
        java.util.Map<String, Object> challengeResponse
) {
    public static MfaStepResult ok() {
        return new MfaStepResult(true, null);
    }

    public static MfaStepResult fail() {
        return new MfaStepResult(false, null);
    }

    public static MfaStepResult challenge(java.util.Map<String, Object> body) {
        return new MfaStepResult(false, body);
    }

    public boolean isChallenge() {
        return challengeResponse != null;
    }
}
