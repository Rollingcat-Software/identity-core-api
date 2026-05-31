package com.fivucsas.identity.application.dto.response;

/**
 * Response for {@code POST /auth/login/preflight} (identifier-first email step).
 *
 * <p>{@code eligible} is the original tenant-eligibility signal (always true
 * here — a mismatch throws 403 upstream). {@code loginConfig} is added so the
 * cross-tenant dashboard, which carries no tenantId/clientId, can resolve the
 * caller's ACTUAL tenant flow (Layer-1 methods + step count) from the typed
 * email and render the real flow ("1/3" + the configured Layer-1) instead of
 * the hardcoded platform PASSWORD-first/totalSteps=1 default. Backward
 * compatible: pre-existing callers read only {@code eligible}.
 */
public record LoginPreflightResponse(boolean eligible, LoginConfigResponse loginConfig) {
}
