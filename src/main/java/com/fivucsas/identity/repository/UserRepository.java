package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * JPA Repository for User entity.
 *
 * Extends JpaRepository for Spring Data JPA functionality.
 * Contains all query methods needed by the application.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // JPA-specific query methods

    /**
     * Resolves a user by email.
     *
     * <p><b>P1-6 (data-correctness, 2026-06-02):</b> this used to be a plain
     * JPQL query returning {@code Optional<User>}. The global active-email
     * uniqueness ({@code idx_users_email_unique}, V7) keeps the normal case
     * single-row, but account-linking (V66/V67/V70 — "same email = same
     * person") deliberately allows the SAME email to hold memberships in
     * several tenants (see V67's "NOT a global unique" rationale). With the
     * Hibernate {@code tenantFilter} disabled (the self-lookup path —
     * {@link com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass}),
     * such an identity matches more than one live row, and the {@code Optional}
     * single-result contract then throws {@code NonUniqueResultException} →
     * opaque HTTP 500 on the auth/caller-resolution path.
     *
     * <p>Fix: delegate to a deterministically-ORDERED, single-row query so the
     * method NEVER throws on multiplicity. The normal single-row login case is
     * unchanged (one match → that match). When duplicates exist we return the
     * OLDEST membership (the person's original row; {@code createdAt ASC}, then
     * {@code id ASC} as a stable tie-break) instead of failing. This keeps the
     * {@code @SQLRestriction("deleted_at IS NULL")} soft-delete guard and the
     * {@code tenantFilter} intact (still a JPQL entity query — NOT a native
     * query — so a caller running under an active tenant filter is still scoped
     * to its tenant, and a tenant-scoped lookup that matches one row behaves
     * exactly as before).</p>
     */
    default Optional<User> findByEmail(String email) {
        List<User> matches = findByEmailOrdered(email, PageRequest.of(0, 1));
        return matches.isEmpty() ? Optional.empty() : Optional.of(matches.get(0));
    }

    /**
     * Deterministically-ordered email lookup backing {@link #findByEmail(String)}.
     * Caller passes {@code PageRequest.of(0, 1)} to fetch at most the oldest match.
     * Not intended for direct use elsewhere — use {@link #findByEmail(String)}.
     */
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.deletedAt IS NULL "
            + "ORDER BY u.createdAt ASC, u.id ASC")
    List<User> findByEmailOrdered(@Param("email") String email, Pageable pageable);

    @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.email = :email AND u.deletedAt IS NULL")
    boolean existsByEmail(@Param("email") String email);

    /**
     * Lightweight lookup of a user's tenant ID by user ID.
     *
     * Used by the audit-log writer (AuditLogAdapter) to populate
     * {@code audit_logs.tenant_id} without loading the full User aggregate
     * for every audit row. This is on the hot path for every authenticated
     * request, so we avoid initializing the tenant proxy.
     *
     * @param userId the user ID
     * @return the tenant ID, or empty if the user does not exist or has no tenant
     */
    @Query("SELECT u.tenant.id FROM User u WHERE u.id = :userId")
    Optional<UUID> findTenantIdById(@Param("userId") UUID userId);

    List<User> findByStatus(UserStatus status);

    long countByStatus(UserStatus status);

    long countByIsBiometricEnrolled(boolean enrolled);

    @Query("SELECT COALESCE(SUM(u.verificationCount), 0) FROM User u")
    Long sumVerificationCount();

    @Query("SELECT u FROM User u WHERE " +
            "LOWER(CONCAT(u.firstName, ' ', u.lastName)) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
            "u.idNumber LIKE CONCAT('%', :query, '%')")
    List<User> searchUsers(@Param("query") String query);

    /**
     * Find expired guest users that are still active.
     */
    @Query("SELECT u FROM User u WHERE u.userType = 'GUEST' " +
           "AND u.expiresAt IS NOT NULL AND u.expiresAt < :now " +
           "AND u.status = 'ACTIVE'")
    List<User> findExpiredGuests(@Param("now") Instant now);

    /**
     * Find users by tenant and user type.
     */
    @Query("SELECT u FROM User u WHERE u.tenant.id = :tenantId AND u.userType = :userType " +
           "AND u.status = 'ACTIVE'")
    List<User> findByTenantIdAndUserType(@Param("tenantId") UUID tenantId,
                                          @Param("userType") String userType);

    /**
     * Count active users by tenant and user type.
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.tenant.id = :tenantId " +
           "AND u.userType = :userType AND u.status = 'ACTIVE'")
    long countByTenantIdAndUserType(@Param("tenantId") UUID tenantId,
                                     @Param("userType") String userType);

    /**
     * Count all users by tenant (regardless of status).
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.tenant.id = :tenantId")
    long countByTenantId(@Param("tenantId") UUID tenantId);

    /**
     * Ids of all non-deleted users in a tenant. The {@code @SQLRestriction} on
     * {@link User} already filters soft-deleted rows. Returns ids only (no User
     * graph) so callers in the application layer can aggregate per-user data
     * without importing the entity.
     */
    @Query("SELECT u.id FROM User u WHERE u.tenant.id = :tenantId")
    List<UUID> findIdsByTenantId(@Param("tenantId") UUID tenantId);

    @Query("SELECT u FROM User u WHERE u.passwordResetToken = :token AND u.deletedAt IS NULL")
    Optional<User> findByPasswordResetToken(@Param("token") String token);

    @Query("SELECT u FROM User u WHERE u.emailVerificationToken = :token AND u.deletedAt IS NULL")
    Optional<User> findByEmailVerificationToken(@Param("token") String token);

    /**
     * Find all users with roles eagerly fetched (avoids N+1 query).
     * Uses EntityGraph to JOIN FETCH userRoles and their associated roles.
     */
    @EntityGraph(attributePaths = {"userRoles", "userRoles.role", "userRoles.role.permissions"})
    @Query("SELECT u FROM User u")
    Page<User> findAllWithRoles(Pageable pageable);

    @EntityGraph(attributePaths = {"userRoles", "userRoles.role", "userRoles.role.permissions"})
    @Query("SELECT u FROM User u WHERE u.tenant.id = :tenantId")
    Page<User> findAllByTenantIdWithRoles(@Param("tenantId") UUID tenantId, Pageable pageable);

    @Query("SELECT u FROM User u WHERE u.tenant.id = :tenantId AND (" +
            "LOWER(CONCAT(u.firstName, ' ', u.lastName)) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :query, '%')) OR " +
            "u.idNumber LIKE CONCAT('%', :query, '%'))")
    List<User> searchUsersByTenant(@Param("tenantId") UUID tenantId, @Param("query") String query);

    /**
     * Finds users soft-deleted before the given cutoff — candidates for permanent
     * purge under the 30-day retention window (GDPR Art. 17 / KVKK).
     *
     * @param cutoff users with {@code deletedAt < cutoff} are returned
     * @param pageable pagination for batched purge
     * @return page of purge-eligible users
     */
    // Native query bypasses the entity's @SQLRestriction("deleted_at IS NULL") so we
    // can actually find soft-deleted rows for the 30-day purge window.
    @Query(
        value = "SELECT * FROM users u WHERE u.deleted_at IS NOT NULL AND u.deleted_at < :cutoff",
        countQuery = "SELECT COUNT(*) FROM users u WHERE u.deleted_at IS NOT NULL AND u.deleted_at < :cutoff",
        nativeQuery = true
    )
    Page<User> findPurgeCandidates(@Param("cutoff") Instant cutoff, Pageable pageable);

    /**
     * GDPR Art. 17 / KVKK hard-purge of a single user row.
     *
     * <p>Required because {@link User} carries {@link org.hibernate.annotations.SQLDelete @SQLDelete}
     * which rewrites JPA delete()/deleteById() into a soft-delete UPDATE. Without this
     * native escape hatch, {@code SoftDeletePurgeJob} would loop forever rereading the
     * same already-soft-deleted rows.</p>
     *
     * <p>Caller must wrap the call in a transaction that runs
     * {@code SET LOCAL app.allow_hard_delete = 'on'} first, otherwise the V53 BEFORE-DELETE
     * trigger blocks the row removal.</p>
     *
     * @return rows affected (0 if id missing, 1 on success)
     */
    @Modifying
    @Query(value = "DELETE FROM users WHERE id = :id", nativeQuery = true)
    int hardDeleteById(@Param("id") UUID id);

    /**
     * Resolves the CANONICAL biometric enrollment for a person (identity) for a
     * given method, EXCLUDING the requesting tenant (Model A, Phase 3).
     *
     * <p>"Canonical" = the membership ({@code users} row) under the SAME identity,
     * in a DIFFERENT tenant, that has an ENROLLED enrollment for {@code method}.
     * The api routes a consented cross-tenant verify to this row's {@code user_id}
     * (the bio face store is keyed by {@code user_id}). The oldest such enrollment
     * wins (deterministic; the person's original enrollment), returned first.</p>
     *
     * <p><b>Native query</b> — deliberately bypasses the Hibernate
     * {@code @Filter(tenantFilter)} on {@code User}/{@code UserEnrollment} and the
     * {@code @SQLRestriction("deleted_at IS NULL")} is re-applied explicitly. This
     * is a CONTROLLED cross-tenant read: it is reached ONLY after a consent grant
     * has been verified by {@code BiometricConsentResolver}, never on the open
     * read path. Returns {@code [user_id, tenant_id]} pairs; the caller takes the
     * first (oldest) and forwards both to the existing bio verify so tenant-scoped
     * voice/search predicates keep matching the canonical tenant.</p>
     *
     * @param identityId      the person whose canonical enrollment to find
     * @param method          the {@code AuthMethodType} name (e.g. {@code FACE})
     * @param excludeTenantId the requesting tenant — its own enrollments are
     *                        excluded (same-tenant verify is handled by the
     *                        unchanged existing path)
     * @return rows of {@code (user_id, tenant_id)}, oldest enrollment first
     */
    @Query(value =
            "SELECT u.id AS user_id, u.tenant_id AS tenant_id "
            + "FROM users u "
            + "JOIN user_enrollments e ON e.user_id = u.id "
            + "WHERE u.identity_id = :identityId "
            + "  AND u.deleted_at IS NULL "
            + "  AND u.tenant_id <> :excludeTenantId "
            + "  AND e.auth_method_type = :method "
            + "  AND e.status = 'ENROLLED' "
            + "ORDER BY e.enrolled_at ASC NULLS LAST, e.created_at ASC",
            nativeQuery = true)
    List<Object[]> findCanonicalEnrollment(@Param("identityId") UUID identityId,
                                           @Param("method") String method,
                                           @Param("excludeTenantId") UUID excludeTenantId);

    /** Reads a user's identity_id without initializing the lazy identity proxy. */
    @Query("SELECT u.identityId FROM User u WHERE u.id = :userId")
    Optional<UUID> findIdentityIdById(@Param("userId") UUID userId);

    /**
     * Whether the given identity holds a (non-deleted) membership in the given
     * tenant (Model A, Phase 3). Backs the consent-grant guard: a caller may only
     * manage biometric consent for a tenant where they actually have a membership.
     *
     * <p>Native query so it does NOT get scoped by the Hibernate
     * {@code tenantFilter} — the check is INTENTIONALLY cross-tenant (the caller's
     * own identity spans tenants). Identity ownership is already proven by the
     * controller (the {@code identityId} comes from the authenticated caller), so
     * this is not a cross-tenant leak.</p>
     */
    @Query(value =
            "SELECT EXISTS (SELECT 1 FROM users u "
            + "WHERE u.identity_id = :identityId AND u.tenant_id = :tenantId "
            + "AND u.deleted_at IS NULL)",
            nativeQuery = true)
    boolean identityHasMembershipInTenant(@Param("identityId") UUID identityId,
                                          @Param("tenantId") UUID tenantId);

    /**
     * Re-points a membership's {@code identity_id} FK (Phase-2 account linking).
     *
     * <p>Issued as a bulk native UPDATE so the link/unlink flow never has to load
     * the full {@link User} aggregate (and never has to call a setter on the
     * intentionally setter-less {@code identity} association). The owning
     * {@code IdentityLinkUserAdapter} clears the persistence context after
     * calling this so subsequent reads see the new FK.</p>
     *
     * @param userId        the membership to re-point
     * @param identityId    the identity that should now own the membership
     * @return rows affected (1 on success, 0 if the id is missing)
     */
    @Modifying
    @Query(value = "UPDATE users SET identity_id = :identityId WHERE id = :userId",
            nativeQuery = true)
    int updateIdentityId(@Param("userId") UUID userId,
                         @Param("identityId") UUID identityId);

    /**
     * All non-deleted memberships ({@code users} rows) that belong to a given
     * identity (Phase-2 account linking). Cross-tenant by design — an identity's
     * memberships span tenants (Model A); callers run this with the Hibernate
     * tenant filter bypassed because the rows are the one person's own.
     */
    @Query("SELECT u FROM User u WHERE u.identity.id = :identityId")
    List<User> findByIdentityId(@Param("identityId") UUID identityId);
}
