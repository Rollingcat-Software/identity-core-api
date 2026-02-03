package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
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
    // Domain methods inherited from domain.repository.UserRepository

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
}
