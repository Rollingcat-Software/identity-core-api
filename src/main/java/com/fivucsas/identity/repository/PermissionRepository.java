package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for Permission entity.
 * Provides CRUD operations and custom queries for permissions.
 */
@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    /**
     * Find permission by its unique name.
     * @param name the permission name (e.g., "user.read")
     */
    Optional<Permission> findByName(String name);

    /**
     * Find all permissions for a specific resource.
     * @param resource the resource name (e.g., "user", "biometric")
     */
    List<Permission> findByResource(String resource);

    /**
     * Find all permissions for multiple resources.
     */
    List<Permission> findByResourceIn(Collection<String> resources);

    /**
     * Find permission by resource and action combination.
     * @param resource the resource name
     * @param action the action name
     */
    @Query("SELECT p FROM Permission p WHERE p.resource = :resource AND p.action = :action")
    Optional<Permission> findByResourceAndAction(@Param("resource") String resource,
                                                  @Param("action") String action);

    /**
     * Check if a permission exists by name.
     */
    boolean existsByName(String name);

    /**
     * Find all permissions ordered by resource and action.
     */
    @Query("SELECT p FROM Permission p ORDER BY p.resource, p.action")
    List<Permission> findAllOrdered();

    /**
     * Find permissions by IDs.
     */
    List<Permission> findByIdIn(Collection<UUID> ids);
}
