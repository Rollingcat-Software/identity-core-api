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

    // NFC document (T2-A, INVESTIGATION 2026-05-07 P1)
    // Emitted by NfcController#verifyMrz. Metadata carries a masked document
    // number (last 4 only) and the issuing country so audit consumers can
    // spot anomalous sources without storing the full document identifier.
    NFC_DOCUMENT_VERIFIED,
    NFC_DOCUMENT_VERIFICATION_FAILED,

    // Settings
    SETTINGS_UPDATED,
    SECURITY_SETTINGS_UPDATED,
    NOTIFICATION_SETTINGS_UPDATED,
    APPEARANCE_SETTINGS_UPDATED,

    // OAuth2 / OIDC (Phase D5)
    // Recorded for every code_verifier mismatch, code reuse, or expired/unknown
    // authorization code at /oauth2/token. Carries clientId + actorIp + a
    // PkceFailureReason in metadata. Does NOT log the verifier or challenge —
    // those are the secret being attacked.
    PKCE_FAILURE
}
