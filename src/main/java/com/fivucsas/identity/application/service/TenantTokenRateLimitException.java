package com.fivucsas.identity.application.service;

/**
 * Thrown by {@link OAuth2Service#exchangeCode} when the per-tenant
 * {@code /oauth2/token} success-path bucket is empty. The controller
 * catches this and emits HTTP 429 + {@code Retry-After} per RFC 6585.
 *
 * <p>INVESTIGATION_MASTER_2026-05-07 §"developer/tenant constraints":
 * "No per-tenant rate-limit bucket — only per-IP/userId/clientId."</p>
 */
public class TenantTokenRateLimitException extends RuntimeException {

    private final long retryAfterSeconds;

    public TenantTokenRateLimitException(long retryAfterSeconds) {
        super("Per-tenant /oauth2/token rate limit exceeded; retry after "
                + retryAfterSeconds + "s");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
