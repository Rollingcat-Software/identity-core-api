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
     * Deletes a tenant.
     */
    void deleteTenant(String tenantId);
}
