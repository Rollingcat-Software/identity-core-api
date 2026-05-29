package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.entity.IdentityTenantBiometricConsent;

import java.time.Instant;
import java.util.UUID;

/**
 * A single per-tenant biometric consent row, as seen by the owning identity
 * (Model A, Phase 3).
 */
public record BiometricConsentResponse(
        UUID id,
        UUID tenantId,
        String method,
        boolean granted,
        Instant grantedAt,
        Instant revokedAt
) {
    public static BiometricConsentResponse from(IdentityTenantBiometricConsent c) {
        return new BiometricConsentResponse(
                c.getId(),
                c.getTenantId(),
                c.getMethod(),
                c.isGranted(),
                c.getGrantedAt(),
                c.getRevokedAt());
    }
}
