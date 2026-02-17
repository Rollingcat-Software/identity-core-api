package com.fivucsas.identity.domain.model.auth;

public enum AuthStepStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    SKIPPED,
    DELEGATED
}
