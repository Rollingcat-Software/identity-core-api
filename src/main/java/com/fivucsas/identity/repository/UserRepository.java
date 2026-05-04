package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import org.springframework.data.domain.Page;
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

    @Query("SELECT u FROM User u WHERE u.email = :email AND u.deletedAt IS NULL")
    Optional<User> findByEmail(@Param("email") String email);

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
}
