package com.fivucsas.identity.application.dto.command;

import lombok.Builder;
import lombok.Getter;

/**
 * Command for public self-service tenant onboarding
 * ({@code POST /api/v1/onboarding/register}).
 *
 * <p>Unlike {@link CreateTenantCommand} (ROOT-only, creates a bare tenant), this
 * command drives the full self-service flow: tenant + first TENANT_ADMIN user +
 * per-tenant TENANT_ADMIN role + primary email-domain claim + default APP_LOGIN
 * auth flow + an email-verification mail. The tenant is created in a
 * PENDING/TRIAL state and only activated once the admin verifies their email.</p>
 */
@Getter
@Builder
public class RegisterTenantCommand {

    /** Organisation display name (also the unique {@code tenants.name}). */
    private final String orgName;

    /**
     * Optional URL-safe slug. When blank it is derived from {@link #orgName} and
     * made unique by appending a numeric suffix on collision.
     */
    private final String slug;

    private final String adminEmail;
    private final String adminPassword;
    private final String adminFirstName;
    private final String adminLastName;

    /**
     * Optional primary email domain to claim for the new tenant. When blank it
     * is derived from the domain part of {@link #adminEmail}.
     */
    private final String emailDomain;

    private final String ipAddress;
    private final String userAgent;
}
