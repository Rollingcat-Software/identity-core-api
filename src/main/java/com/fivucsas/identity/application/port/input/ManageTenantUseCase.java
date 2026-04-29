package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.CreateTenantCommand;
import com.fivucsas.identity.application.dto.command.UpdateTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantResponse;

import java.util.List;

/**
 * Input port for tenant management operations.
 *
 * Following Hexagonal Architecture - this defines what the application can do.
 */
public interface ManageTenantUseCase {

    /**
     * Creates a new tenant.
     */
    TenantResponse createTenant(CreateTenantCommand command);

    /**
     * Gets tenant by ID.
     */
    TenantResponse getTenantById(String tenantId);

    /**
     * Gets tenant by slug.
     */
    TenantResponse getTenantBySlug(String slug);

    /**
     * Gets all tenants.
     */
    List<TenantResponse> getAllTenants();

    /**
     * Updates a tenant.
     */
    TenantResponse updateTenant(UpdateTenantCommand command);

    /**
     * Activates a tenant.
     */
    TenantResponse activateTenant(String tenantId);

    /**
     * Suspends a tenant.
     */
    TenantResponse suspendTenant(String tenantId);

    /**
     * Deletes a tenant. Implemented as a SOFT delete (sets
     * {@code tenants.deleted_at = NOW()}) — see
     * {@link #softDeleteTenant(java.util.UUID)}.
     *
     * <p>Hard delete is forbidden because {@code tenants.id} is referenced by
     * ~13 child tables, most with {@code ON DELETE CASCADE}; a hard delete
     * would silently wipe ~10 dependent tables. Hibernate's
     * {@code @SQLDelete} on the entity transparently routes
     * {@code deleteById} through the soft path, so this method is safe.
     */
    void deleteTenant(String tenantId);

    /**
     * Soft-deletes a tenant by id (sets {@code tenants.deleted_at = NOW()}).
     * The row remains in the database but is invisible to default JPA
     * finds via the entity's {@code @SQLRestriction}. Cascade chains are
     * NOT triggered. Use this in preference to {@link #deleteTenant(String)}
     * when calling code already has a {@code UUID} in hand.
     *
     * @param tenantId the tenant to soft-delete
     * @throws com.fivucsas.identity.domain.exception.TenantNotFoundException
     *         if no live tenant matches {@code tenantId}
     */
    void softDeleteTenant(java.util.UUID tenantId);
}
