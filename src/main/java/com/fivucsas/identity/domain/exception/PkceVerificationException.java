package com.fivucsas.identity.domain.exception;

import com.fivucsas.identity.domain.model.PkceFailureReason;

/**
 * Thrown by {@code OAuth2Service.exchangeCode} when an authorization-code or
 * PKCE check fails at the token endpoint. Distinct from
 * {@link IllegalArgumentException} so the controller can:
 *
 * <ul>
 *   <li>Audit-log the failure with {@code clientId} + reason + actor IP
 *       (Phase D5a).</li>
 *   <li>Increment a per-{@code clientId} failure bucket and return 429 with
 *       {@code Retry-After} when the bucket is empty (Phase D5b).</li>
 * </ul>
 *
 * <p>The wire response remains RFC 6749 §5.2 {@code invalid_grant} — this
 * exception is purely an internal carrier of audit/rate-limit context. It
 * deliberately does NOT include the code_verifier, code_challenge, or any
 * tokens.</p>
 */
public class PkceVerificationException extends RuntimeException {

    private final String clientId;
    private final PkceFailureReason reason;

    public PkceVerificationException(String clientId, PkceFailureReason reason, String message) {
        super(message);
        this.clientId = clientId;
        this.reason = reason;
    }

    public String getClientId() {
        return clientId;
    }

    public PkceFailureReason getReason() {
        return reason;
    }
}
