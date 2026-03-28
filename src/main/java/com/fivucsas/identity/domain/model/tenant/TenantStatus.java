package com.fivucsas.identity.domain.model.tenant;

/**
 * Domain enum for tenant lifecycle status.
 * Pure domain concept - no infrastructure dependencies.
 */
public enum TenantStatus {
    ACTIVE,
    INACTIVE,
    SUSPENDED,
    TRIAL,
    PENDING
}
