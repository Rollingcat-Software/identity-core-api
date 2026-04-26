package com.fivucsas.identity.domain.model;

/**
 * Categorisation of PKCE/authorization-code-exchange failures.
 *
 * <p>Used as the {@code failureReason} field on {@code AuditAction.PKCE_FAILURE}
 * audit rows (Phase D5a). The enum captures the why of a PKCE/code rejection
 * at {@code /oauth2/token} so SOC analysts can distinguish a legitimate user
 * mistyping a verifier (rare, low signal) from a cross-client code-injection
 * or replay attack (high signal).</p>
 *
 * <p>NEVER include the actual {@code code_verifier} or {@code code_challenge}
 * in the audit row — the verifier is the secret that protects the code, and
 * an attacker brute-forcing it would otherwise see successive guesses logged
 * back to them via tenant audit-log views.</p>
 */
public enum PkceFailureReason {

    /** Authorization code key not present in Redis (expired TTL or never issued). */
    CODE_NOT_FOUND,

    /** Authorization code was found but is past its 10-minute TTL window. */
    CODE_EXPIRED,

    /**
     * Authorization code was already consumed by an earlier {@code /token} call.
     * Detected when Redis returns null after a prior successful exchange — the
     * second exchange is treated as a replay attack.
     */
    CODE_REUSED,

    /**
     * Stored authorization-code metadata could not be parsed (corrupted JSON or
     * legacy pipe payload that failed split). Should never happen in practice.
     */
    CORRUPT_DATA,

    /**
     * The authorization request included a {@code code_challenge} (PKCE flow)
     * but the token request did not include a {@code code_verifier}. RFC 7636
     * §4.6: token endpoint MUST require the verifier when challenge was set.
     */
    MISSING_VERIFIER,

    /**
     * SHA-256({@code code_verifier}) did not equal the stored
     * {@code code_challenge}, or {@code plain} method comparison failed.
     * This is the signature of a code-interception attack — the attacker has
     * the code but not the verifier.
     */
    VERIFIER_MISMATCH
}
