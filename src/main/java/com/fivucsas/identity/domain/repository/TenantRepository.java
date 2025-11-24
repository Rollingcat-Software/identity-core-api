package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Domain repository interface for Tenant aggregate.
 * Following Hexagonal Architecture - this is an output port.
 *
 * Defines the contract for tenant persistence operations.
 * Implementation provided by infrastructure layer.
 */
public interface TenantRepository {

    /**
     * Saves a tenant (create or update).
     */
    Tenant save(Tenant tenant);

    /**
     * Finds tenant by ID.
     */
    Optional<Tenant> findById(UUID id);

    /**
     * Finds tenant by slug.
     */
    Optional<Tenant> findBySlug(String slug);

    /**
     * Finds tenant by name.
     */
    Optional<Tenant> findByName(String name);

    /**
     * Finds all tenants.
     */
    List<Tenant> findAll();

    /**
     * Finds tenants by status.
     */
    List<Tenant> findByStatus(TenantStatus status);

    /**
     * Checks if tenant exists by slug.
     */
    boolean existsBySlug(String slug);

    /**
     * Checks if tenant exists by name.
     */
    boolean existsByName(String name);

    /**
     * Deletes a tenant.
     */
    void delete(Tenant tenant);

    /**
     * Counts total tenants.
     */
    long count();

    /**
     * Counts tenants by status.
     */
    long countByStatus(TenantStatus status);
}
