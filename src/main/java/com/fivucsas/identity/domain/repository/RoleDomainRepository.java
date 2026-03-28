package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.domain.model.role.Role;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Pure domain repository interface for Role aggregate.
 * Returns domain model objects only - no JPA entity leakage.
 *
 * This is the target interface for new code following Hexagonal Architecture.
 * The existing RoleRepositoryPort (returning JPA entities) remains for backward compatibility.
 *
 * Implementation: infrastructure/adapter/RoleDomainRepositoryAdapter
 */
public interface RoleDomainRepository {

    /**
     * Finds a role by ID with permissions loaded.
     */
    Optional<Role> findById(UUID id);

    /**
     * Finds a role by ID with permissions eagerly loaded.
     */
    Optional<Role> findByIdWithPermissions(UUID id);

    /**
     * Finds a role by name (active only, not soft-deleted).
     */
    Optional<Role> findByNameAndDeletedAtIsNull(String name);

    /**
     * Finds a role by tenant and name (active only, not soft-deleted).
     */
    Optional<Role> findByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name);

    /**
     * Checks if a role exists for a tenant with the given name.
     */
    boolean existsByTenantIdAndNameAndDeletedAtIsNull(UUID tenantId, String name);

    /**
     * Finds all roles with permissions.
     */
    List<Role> findAllWithPermissions();

    /**
     * Finds all active roles with permissions.
     */
    List<Role> findAllActiveWithPermissions();

    /**
     * Finds all roles for a tenant with permissions.
     */
    List<Role> findByTenantIdWithPermissions(UUID tenantId);

    /**
     * Saves a role (create or update).
     */
    Role save(Role role);
}
