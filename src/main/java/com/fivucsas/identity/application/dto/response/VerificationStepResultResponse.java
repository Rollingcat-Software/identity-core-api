package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.VerificationStepStatus;
import com.fivucsas.identity.entity.VerificationStepResult;

import java.time.Instant;
import java.util.UUID;

public record VerificationStepResultResponse(
    UUID id,
    int stepNumber,
    String stepType,
    VerificationStepStatus status,
    Double confidence,
    String resultData,
    String errorMessage,
    Instant startedAt,
    Instant completedAt
) {
    public static VerificationStepResultResponse from(VerificationStepResult entity) {
        return new VerificationStepResultResponse(
            entity.getId(),
            entity.getStepNumber(),
            entity.getStepType(),
            entity.getStatus(),
            entity.getConfidence(),
            entity.getResultData(),
            entity.getErrorMessage(),
            entity.getStartedAt(),
            entity.getCompletedAt()
        );
    }
}
