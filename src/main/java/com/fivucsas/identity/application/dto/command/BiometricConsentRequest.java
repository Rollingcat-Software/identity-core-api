package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/**
 * Grant / revoke a per-tenant biometric consent for the CALLER's identity
 * (Model A, Phase 3).
 *
 * @param tenantId the tenant the consent applies to (the caller must have a
 *                 membership there)
 * @param method   optional {@code AuthMethodType} name (e.g. {@code FACE}).
 *                 {@code null} = all biometric methods.
 * @param granted  {@code true} to grant, {@code false} to revoke
 */
public record BiometricConsentRequest(
        @NotNull UUID tenantId,
        String method,
        @NotNull Boolean granted
) {}
