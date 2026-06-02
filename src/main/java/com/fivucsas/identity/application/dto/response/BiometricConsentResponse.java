package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.entity.IdentityTenantBiometricConsent;

import java.time.Instant;
import java.util.UUID;

/**
 * A single per-tenant biometric consent row, as seen by the owning identity
 * (Model A, Phase 3).
 *
 * <p>{@code tenantName} is the resolved display name for {@code tenantId}; it is
 * null when the tenant is missing/soft-deleted so the UI can fall back to the raw
 * id (the web side renders {@code tenantName ?? tenantId}).</p>
 */
public record BiometricConsentResponse(
        UUID id,
        UUID tenantId,
        String tenantName,
        String method,
        boolean granted,
        Instant grantedAt,
        Instant revokedAt
) {
    /**
     * Builds a response without a resolved tenant name (name left null). Prefer
     * {@link #from(IdentityTenantBiometricConsent, String)} so the UI can show the
     * tenant name instead of the raw UUID.
     */
    public static BiometricConsentResponse from(IdentityTenantBiometricConsent c) {
        return from(c, null);
    }

    /**
     * Builds a response with an optional resolved tenant display name.
     *
     * @param tenantName the resolved tenant name, or null when the tenant is
     *                   missing/soft-deleted (UI falls back to the UUID)
     */
    public static BiometricConsentResponse from(IdentityTenantBiometricConsent c, String tenantName) {
        return new BiometricConsentResponse(
                c.getId(),
                c.getTenantId(),
                tenantName,
                c.getMethod(),
                c.isGranted(),
                c.getGrantedAt(),
                c.getRevokedAt());
    }
}
