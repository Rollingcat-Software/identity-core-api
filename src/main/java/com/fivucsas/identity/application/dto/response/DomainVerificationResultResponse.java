package com.fivucsas.identity.application.dto.response;

import lombok.Builder;
import lombok.Getter;

/**
 * Result of {@code POST /api/v1/tenants/{tenantId}/email-domains/{domain}/verify}.
 *
 * <p>On success: {@code {verified: true}} (HTTP 200). On failure the controller
 * returns this same body with {@code verified=false} and a machine-readable
 * {@link #reason}, mapped to HTTP 422 (record not found / mismatch) or 409
 * (no challenge issued yet).</p>
 */
@Getter
@Builder
public class DomainVerificationResultResponse {

    /** The email domain that was checked. */
    private final String domain;

    /** Whether ownership was proven (TXT record present and matching). */
    private final boolean verified;

    /**
     * Machine-readable failure reason when {@code verified=false}; {@code null}
     * on success. One of:
     * <ul>
     *   <li>{@code NO_CHALLENGE} — no verification token has been requested yet</li>
     *   <li>{@code RECORD_NOT_FOUND} — the expected TXT record was not present</li>
     *   <li>{@code ALREADY_VERIFIED} — the domain was already verified (idempotent)</li>
     * </ul>
     */
    private final String reason;

    /** Human-readable explanation for the UI; {@code null} on plain success. */
    private final String message;
}
