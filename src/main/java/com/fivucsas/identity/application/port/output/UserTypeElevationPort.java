package com.fivucsas.identity.application.port.output;

import java.util.UUID;

/**
 * Output port for keeping a user's platform tier ({@code users.user_type}) in
 * sync with the RBAC roles they are granted — the ongoing half of the role /
 * user_type unification (see {@code docs/IDENTITY_ROLE_UNIFICATION.md}).
 *
 * <p><b>Conceptual model.</b> {@code user_type} is the SOLE authority for the
 * platform tier (ROOT &gt; TENANT_ADMIN &gt; TENANT_MEMBER &gt; GUEST) — every
 * backend gate keys off it. The seeded "tier roles" ({@code ROOT}, formerly
 * {@code SUPER_ADMIN}, and {@code TENANT_ADMIN}) used to be a second, drifting
 * source of truth. The V69 migration did the one-time backfill; this port keeps
 * the two aligned going forward: when an admin grants a user the ROOT or a
 * TENANT_ADMIN role, the user's tier is ELEVATED to match.</p>
 *
 * <p><b>Elevate-only (v1).</b> Granting a higher tier role raises {@code user_type};
 * it never lowers it. Revoking a role does NOT auto-demote — demotion stays an
 * explicit admin action, so an accidental revoke can't silently strip access.</p>
 *
 * <p><b>Why a port (hexagonal boundary).</b> Mutating {@code user_type} touches
 * the JPA {@code entity.User}, which is fenced behind the
 * {@code UserDomainBoundaryTest} ArchUnit ratchet and must not be imported from
 * {@code application..}. The implementing adapter lives in {@code infrastructure..}
 * (the official bridge) and is the only place that loads {@code entity.User} for
 * this operation. The choke-point service ({@code ManageUserRoleService}) calls
 * this port with plain UUIDs / strings.</p>
 */
public interface UserTypeElevationPort {

    /**
     * Elevates the user's {@code user_type} to match a just-granted role, if the
     * role denotes a higher platform tier than the user currently holds.
     *
     * <ul>
     *   <li>ROOT role (id {@code 10000000-0000-0000-0000-000000000001} OR name
     *       {@code "ROOT"}) → elevate to {@code ROOT}.</li>
     *   <li>any {@code "TENANT_ADMIN"} role (the global template or a per-tenant
     *       one) → elevate to at least {@code TENANT_ADMIN}.</li>
     *   <li>any other (plain permission) role → no change.</li>
     * </ul>
     *
     * <p>ELEVATE-ONLY: never lowers an existing higher tier (a TENANT_ADMIN role
     * grant leaves a ROOT user at ROOT). Idempotent and best-effort — a sync
     * hiccup must never roll back the role assignment, so implementations MUST
     * NOT throw.</p>
     *
     * @param userId   the user who was just granted the role
     * @param roleId   the granted role's id
     * @param roleName the granted role's name (case-insensitive)
     */
    void elevateForGrantedRole(UUID userId, UUID roleId, String roleName);
}
