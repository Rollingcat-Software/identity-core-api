package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
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

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

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

    Optional<User> findByPasswordResetToken(String token);

    Optional<User> findByEmailVerificationToken(String token);

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
    @Query("SELECT u FROM User u WHERE u.deletedAt IS NOT NULL AND u.deletedAt < :cutoff")
    Page<User> findPurgeCandidates(@Param("cutoff") Instant cutoff, Pageable pageable);
}
