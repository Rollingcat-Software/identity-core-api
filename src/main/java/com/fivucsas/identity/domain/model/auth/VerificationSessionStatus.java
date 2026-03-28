package com.fivucsas.identity.domain.model.auth;

public enum VerificationSessionStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    EXPIRED,
    CANCELLED
}
