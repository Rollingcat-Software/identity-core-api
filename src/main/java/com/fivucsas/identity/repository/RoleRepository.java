package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for Role entity.
 * Provides CRUD operations and custom queries for roles.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    /**
     * Find role by name (non-deleted).
     */
    Optional<Role> findByNameAndDeletedAtIsNull(String name);

    /**
     * Find role by tenant and name (non-deleted).
     */
    Optional<Role> findByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name);

    /**
     * Find all active roles for a tenant (non-deleted).
     */
    List<Role> findByTenantIdAndDeletedAtIsNullAndActiveTrue(UUID tenantId);

    /**
     * Find all system roles (non-deleted).
     */
    List<Role> findBySystemRoleTrueAndDeletedAtIsNull();

    /**
     * Find all non-deleted roles.
     */
    List<Role> findByDeletedAtIsNull();

    /**
     * Find all active non-deleted roles.
     */
    List<Role> findByDeletedAtIsNullAndActiveTrue();

    /**
     * Check if a role exists by tenant and name (non-deleted).
     */
    boolean existsByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name);

    /**
     * Find role by ID with permissions eagerly loaded (non-deleted).
     */
    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.permissions WHERE r.id = :id AND r.deletedAt IS NULL")
    Optional<Role> findByIdWithPermissions(@Param("id") UUID id);

    /**
     * Find all non-deleted roles with permissions eagerly loaded.
     */
    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.permissions WHERE r.deletedAt IS NULL")
    List<Role> findAllWithPermissions();

    /**
     * Find all active non-deleted roles with permissions eagerly loaded.
     */
    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.permissions WHERE r.deletedAt IS NULL AND r.active = true")
    List<Role> findAllActiveWithPermissions();

    /**
     * Find roles for a tenant with permissions eagerly loaded.
     */
    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.permissions " +
           "WHERE r.tenantId = :tenantId AND r.deletedAt IS NULL AND r.active = true")
    List<Role> findByTenantIdWithPermissions(@Param("tenantId") UUID tenantId);

    /**
     * Find system roles with permissions eagerly loaded.
     */
    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.permissions " +
           "WHERE r.systemRole = true AND r.deletedAt IS NULL")
    List<Role> findSystemRolesWithPermissions();
}
