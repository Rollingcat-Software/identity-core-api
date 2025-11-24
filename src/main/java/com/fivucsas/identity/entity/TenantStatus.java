package com.fivucsas.identity.entity;

/**
 * Enum representing the status of a Tenant.
 */
public enum TenantStatus {
    /**
     * Tenant is active and operational.
     */
    ACTIVE,

    /**
     * Tenant is inactive (disabled).
     */
    INACTIVE,

    /**
     * Tenant is suspended (e.g., payment issues, violation).
     */
    SUSPENDED,

    /**
     * Tenant is in trial period.
     */
    TRIAL,

    /**
     * Tenant is pending activation.
     */
    PENDING
}
