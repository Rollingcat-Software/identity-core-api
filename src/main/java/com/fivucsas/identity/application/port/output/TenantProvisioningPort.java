package com.fivucsas.identity.application.port.output;

import java.util.UUID;

/**
 * Output port that provisions all persistence-layer artifacts for a new
 * self-service tenant in a single transaction.
 *
 * <p>This port exists so the {@code application} layer can orchestrate
 * onboarding without importing {@code entity.User} (forbidden outside the
 * infrastructure/repository/entity/security packages — see
 * {@code UserDomainBoundaryTest}). The infrastructure adapter
 * {@code TenantOnboardingProvisioner} owns the JPA entity wiring.</p>
 */
public interface TenantProvisioningPort {

    /**
     * Creates, in ONE transaction:
     * <ol>
     *   <li>the tenant (in {@code initialStatus});</li>
     *   <li>a per-tenant TENANT_ADMIN role (permissions cloned from the
     *       system role template) — unless one already exists;</li>
     *   <li>the first admin user (TENANT_ADMIN, password hashed,
     *       {@code emailVerified=false}) with the role assigned and a fresh
     *       email-verification token generated;</li>
     *   <li>the primary {@code tenant_email_domains} claim;</li>
     *   <li>a default APP_LOGIN auth flow (PASSWORD + EMAIL_OTP),
     *       {@code is_default=true, is_active=true}.</li>
     * </ol>
     *
     * <p>Uniqueness pre-checks (org name, slug, admin email, email-domain claim)
     * are the CALLER's responsibility; this method assumes they have passed and
     * performs the inserts.</p>
     *
     * @param params the validated, normalised provisioning inputs
     * @return identifiers + the email-verification token for the new admin
     */
    Result provision(Params params);

    /**
     * Activates the tenant that owns the given admin user, transitioning it from
     * its pending onboarding state to {@code ACTIVE}. Idempotent: a no-op if the
     * tenant is already ACTIVE. Skipped (returns {@code false}) when admin
     * approval is still required.
     *
     * @param adminUserId the user whose email was just verified
     * @param requireAdminApproval when true the tenant is left PENDING for a
     *                             ROOT to approve, even after verification
     * @return true if the tenant was activated, false if it was left pending
     */
    boolean activateTenantForVerifiedAdmin(UUID adminUserId, boolean requireAdminApproval);

    /** Validated, normalised inputs for {@link #provision(Params)}. */
    record Params(
            String orgName,
            String slug,
            String adminEmail,
            String hashedPassword,
            String adminFirstName,
            String adminLastName,
            String emailDomain,
            String initialStatus
    ) {}

    /** Output of {@link #provision(Params)}. */
    record Result(
            UUID tenantId,
            UUID adminUserId,
            UUID tenantAdminRoleId,
            String emailVerificationToken
    ) {}
}
