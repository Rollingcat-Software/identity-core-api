package com.fivucsas.identity.application.port.output;

import java.util.UUID;

/**
 * Output port for assigning a tenant's default member role to a freshly
 * auto-provisioned user (default-role-on-join, V64).
 *
 * <p>When a registrant auto-joins a tenant by registering with a VERIFIED email
 * domain ({@code RegisterUserService}), they should land with the tenant's
 * configured baseline role. The entity-level wiring (loading {@code entity.Role}
 * / {@code entity.User}, inserting the {@code user_roles} row) lives in the
 * infrastructure adapter so the application service never imports the JPA role
 * model — keeping the hexagonal boundary clean.</p>
 *
 * <p>JIT scoping note: this is NOT external-IdP JIT provisioning (this platform
 * is the IdP, not a federation consumer). "JIT" here means auto-provisioning the
 * self-registering user into the resolved verified tenant with a default role.</p>
 */
public interface MemberRoleAssignmentPort {

    /**
     * Assigns the tenant's default member role to the given user.
     *
     * <p>Resolution order for the role:</p>
     * <ol>
     *   <li>{@code tenants.default_member_role} (by name), if set and the role
     *       exists for the tenant;</li>
     *   <li>otherwise the seeded baseline role ({@code "USER"}) for the tenant;</li>
     *   <li>otherwise no-op (best-effort — never fails registration).</li>
     * </ol>
     *
     * <p>Idempotent: if the user already holds the resolved role, does nothing.
     * Implementations MUST NOT throw — a role-assignment hiccup must never roll
     * back a successful registration.</p>
     *
     * @param userId   the newly-registered user's id
     * @param tenantId the tenant the user auto-joined
     * @return the name of the role assigned, or {@code null} if none was applied
     */
    String assignDefaultMemberRole(UUID userId, UUID tenantId);
}
