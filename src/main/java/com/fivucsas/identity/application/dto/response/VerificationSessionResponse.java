package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.VerificationSessionStatus;
import com.fivucsas.identity.entity.VerificationSession;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record VerificationSessionResponse(
    UUID id,
    UUID userId,
    UUID tenantId,
    UUID flowId,
    String flowName,
    VerificationSessionStatus status,
    int currentStepNumber,
    Instant startedAt,
    Instant completedAt,
    Instant expiresAt,
    List<VerificationStepResultResponse> steps,
    Instant createdAt,
    Instant updatedAt
) {
    public static VerificationSessionResponse from(VerificationSession entity) {
        List<VerificationStepResultResponse> stepResponses = entity.getStepResults() != null
            ? entity.getStepResults().stream().map(VerificationStepResultResponse::from).toList()
            : List.of();
        return new VerificationSessionResponse(
            entity.getId(),
            entity.getUser().getId(),
            entity.getTenant().getId(),
            entity.getFlow().getId(),
            entity.getFlow().getName(),
            entity.getStatus(),
            entity.getCurrentStepNumber(),
            entity.getStartedAt(),
            entity.getCompletedAt(),
            entity.getExpiresAt(),
            stepResponses,
            entity.getCreatedAt(),
            entity.getUpdatedAt()
        );
    }
}
