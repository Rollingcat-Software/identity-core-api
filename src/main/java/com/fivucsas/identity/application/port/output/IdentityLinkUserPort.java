package com.fivucsas.identity.application.port.output;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for the user/membership-side operations needed by Phase-2
 * account linking ({@code IdentityLinkService}).
 *
 * <p><b>Why this port exists (hexagonal boundary).</b> Account linking has to
 * read and mutate {@code users} rows (the tenant MEMBERSHIPS) — resolve a target
 * membership by email, read its tenant/status, re-point its {@code identity_id},
 * and verify the CALLER's password for step-up. The JPA {@code entity.User}
 * type is fenced behind the {@code UserDomainBoundaryTest} ArchUnit ratchet and
 * MUST NOT be imported from {@code application..}. This port exposes only plain
 * DTOs / UUIDs / strings so the application service stays boundary-clean; the
 * implementing adapter lives in {@code infrastructure..} (the official bridge)
 * and is the only place that touches {@code entity.User}.</p>
 */
public interface IdentityLinkUserPort {

    /**
     * A read-only projection of a tenant membership ({@code users} row) plus its
     * identity / tenant context — everything Phase-2 linking needs without
     * leaking the JPA entity.
     */
    record MembershipView(
            UUID userId,
            UUID identityId,
            String email,
            UUID tenantId,
            String tenantName,
            String role,
            boolean active) {
    }

    /**
     * Resolves a membership by its (case-insensitive) email, if a non-deleted
     * user with that email exists.
     */
    Optional<MembershipView> findMembershipByEmail(String email);

    /**
     * Resolves a membership by its user id, if a non-deleted user exists.
     */
    Optional<MembershipView> findMembershipByUserId(UUID userId);

    /**
     * All memberships ({@code users} rows) that belong to the given identity,
     * fetched WITHOUT the tenant filter (the rows are the one person's own — a
     * cross-tenant read by design for the platform-level identity). Used by
     * {@code GET /identity/me} and to enforce same-tenant link guards.
     */
    List<MembershipView> findMembershipsByIdentityId(UUID identityId);

    /**
     * Verifies that {@code rawPassword} matches the stored password hash of the
     * given user (the caller, for step-up re-authentication). Returns false if
     * the user has no password set or the user does not exist.
     */
    boolean verifyPassword(UUID userId, String rawPassword);

    /**
     * Re-points a membership's {@code identity_id} FK to {@code newIdentityId}.
     * The membership row is otherwise untouched (role/tenant/credentials stay).
     */
    void repointIdentity(UUID userId, UUID newIdentityId);
}
