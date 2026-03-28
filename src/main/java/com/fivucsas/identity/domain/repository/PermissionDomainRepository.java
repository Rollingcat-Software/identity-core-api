package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.domain.model.permission.Permission;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Pure domain repository interface for Permission.
 * Returns domain model objects only - no JPA entity leakage.
 *
 * This is the target interface for new code following Hexagonal Architecture.
 * The existing PermissionRepositoryPort (returning JPA entities) remains for backward compatibility.
 *
 * Implementation: infrastructure/adapter/PermissionDomainRepositoryAdapter
 */
public interface PermissionDomainRepository {

    /**
     * Finds a permission by ID.
     */
    Optional<Permission> findById(UUID id);

    /**
     * Finds all permissions, ordered.
     */
    List<Permission> findAllOrdered();

    /**
     * Finds all permissions for a given resource.
     */
    List<Permission> findByResource(String resource);

    /**
     * Finds permissions by their IDs.
     */
    List<Permission> findByIdIn(List<UUID> ids);
}
