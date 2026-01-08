package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.entity.UserRoleId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Repository for UserRole entity.
 * Manages user-role assignments with support for time-limited roles.
 */
@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UserRoleId> {

    /**
     * Find all role assignments for a user.
     */
    List<UserRole> findByIdUserId(UUID userId);

    /**
     * Find all user assignments for a role.
     */
    List<UserRole> findByIdRoleId(UUID roleId);

    /**
     * Find active (non-expired) role assignments for a user with permissions loaded.
     * This is the main method used for loading user authorities.
     */
    @Query("SELECT ur FROM UserRole ur " +
           "JOIN FETCH ur.role r " +
           "LEFT JOIN FETCH r.permissions " +
           "WHERE ur.id.userId = :userId " +
           "AND r.active = true " +
           "AND r.deletedAt IS NULL " +
           "AND (ur.expiresAt IS NULL OR ur.expiresAt > :now)")
    List<UserRole> findActiveUserRolesWithPermissions(@Param("userId") UUID userId,
                                                       @Param("now") Instant now);

    /**
     * Find all role assignments for a user with role details loaded.
     */
    @Query("SELECT ur FROM UserRole ur " +
           "JOIN FETCH ur.role r " +
           "WHERE ur.id.userId = :userId")
    List<UserRole> findByUserIdWithRole(@Param("userId") UUID userId);

    /**
     * Find all user assignments for a role with user details loaded.
     */
    @Query("SELECT ur FROM UserRole ur " +
           "JOIN FETCH ur.user u " +
           "WHERE ur.id.roleId = :roleId")
    List<UserRole> findByRoleIdWithUser(@Param("roleId") UUID roleId);

    /**
     * Check if a user-role assignment exists.
     */
    boolean existsByIdUserIdAndIdRoleId(UUID userId, UUID roleId);

    /**
     * Delete a specific user-role assignment.
     */
    @Modifying
    @Query("DELETE FROM UserRole ur WHERE ur.id.userId = :userId AND ur.id.roleId = :roleId")
    void deleteByUserIdAndRoleId(@Param("userId") UUID userId, @Param("roleId") UUID roleId);

    /**
     * Delete all role assignments for a user.
     */
    @Modifying
    @Query("DELETE FROM UserRole ur WHERE ur.id.userId = :userId")
    void deleteAllByUserId(@Param("userId") UUID userId);

    /**
     * Delete all user assignments for a role.
     */
    @Modifying
    @Query("DELETE FROM UserRole ur WHERE ur.id.roleId = :roleId")
    void deleteAllByRoleId(@Param("roleId") UUID roleId);

    /**
     * Delete expired role assignments.
     */
    @Modifying
    @Query("DELETE FROM UserRole ur WHERE ur.expiresAt IS NOT NULL AND ur.expiresAt < :now")
    int deleteExpiredAssignments(@Param("now") Instant now);

    /**
     * Count users with a specific role.
     */
    @Query("SELECT COUNT(ur) FROM UserRole ur WHERE ur.id.roleId = :roleId")
    long countByRoleId(@Param("roleId") UUID roleId);

    /**
     * Count roles assigned to a user.
     */
    @Query("SELECT COUNT(ur) FROM UserRole ur WHERE ur.id.userId = :userId")
    long countByUserId(@Param("userId") UUID userId);
}
