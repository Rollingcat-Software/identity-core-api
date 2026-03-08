package com.fivucsas.identity.domain.model;

/**
 * Enumeration of all auditable actions in the system.
 * Used for audit logging and security event tracking.
 */
public enum AuditAction {
    // Authentication
    USER_LOGIN,
    USER_LOGOUT,
    USER_LOGIN_FAILED,
    TOKEN_REFRESH,
    PASSWORD_CHANGE,
    PASSWORD_RESET_REQUEST,
    PASSWORD_RESET,

    // User management
    USER_CREATED,
    USER_UPDATED,
    USER_DELETED,
    USER_STATUS_CHANGED,
    USER_ROLE_ASSIGNED,
    USER_ROLE_REMOVED,

    // Tenant management
    TENANT_CREATED,
    TENANT_UPDATED,
    TENANT_DELETED,
    TENANT_STATUS_CHANGED,

    // Role management
    ROLE_CREATED,
    ROLE_UPDATED,
    ROLE_DELETED,
    PERMISSION_ADDED,
    PERMISSION_REMOVED,

    // Biometric
    BIOMETRIC_ENROLLED,
    BIOMETRIC_VERIFIED,
    BIOMETRIC_VERIFICATION_FAILED,
    BIOMETRIC_DELETED,

    // Settings
    SETTINGS_UPDATED,
    SECURITY_SETTINGS_UPDATED,
    NOTIFICATION_SETTINGS_UPDATED,
    APPEARANCE_SETTINGS_UPDATED
}
