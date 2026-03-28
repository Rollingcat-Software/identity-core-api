package com.fivucsas.identity.domain.model.user;

/**
 * Domain enum for user account status.
 * Pure domain concept - no infrastructure dependencies.
 */
public enum UserStatus {
    ACTIVE,
    INACTIVE,
    SUSPENDED,
    PENDING_ENROLLMENT,
    DELETED,
    LOCKED
}
