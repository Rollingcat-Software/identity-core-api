package com.fivucsas.identity.infrastructure.multitenancy;

import java.util.UUID;

/**
 * ThreadLocal holder for the current tenant context.
 *
 * Following principles:
 * - Thread Safety: Uses ThreadLocal for isolation
 * - Single Responsibility: Only manages tenant context
 */
public final class TenantContext {

    private static final ThreadLocal<UUID> CURRENT_TENANT = new ThreadLocal<>();

    private TenantContext() {
        // Utility class, no instantiation
    }

    /**
     * Sets the current tenant ID for this thread.
     *
     * @param tenantId the tenant ID
     */
    public static void setCurrentTenant(UUID tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    /**
     * Gets the current tenant ID for this thread.
     *
     * @return the tenant ID, or null if not set
     */
    public static UUID getCurrentTenant() {
        return CURRENT_TENANT.get();
    }

    /**
     * Clears the current tenant ID.
     * Should be called after request processing to prevent memory leaks.
     */
    public static void clear() {
        CURRENT_TENANT.remove();
    }

    /**
     * Checks if a tenant is set for the current thread.
     *
     * @return true if tenant is set
     */
    public static boolean hasTenant() {
        return CURRENT_TENANT.get() != null;
    }

    /**
     * Gets the current tenant ID or throws exception if not set.
     *
     * @return the tenant ID
     * @throws IllegalStateException if no tenant is set
     */
    public static UUID requireCurrentTenant() {
        UUID tenantId = CURRENT_TENANT.get();
        if (tenantId == null) {
            throw new IllegalStateException("No tenant context available");
        }
        return tenantId;
    }
}
