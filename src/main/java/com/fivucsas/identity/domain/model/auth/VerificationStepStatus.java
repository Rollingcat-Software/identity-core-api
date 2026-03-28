package com.fivucsas.identity.domain.model.auth;

public enum VerificationStepStatus {
    PENDING,
    IN_PROGRESS,
    COMPLETED,
    FAILED,
    SKIPPED,
    PENDING_REVIEW
}
