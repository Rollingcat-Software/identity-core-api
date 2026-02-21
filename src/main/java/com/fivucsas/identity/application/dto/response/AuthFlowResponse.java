package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AuthFlowResponse(
    UUID id,
    UUID tenantId,
    String name,
    String description,
    OperationType operationType,
    boolean isDefault,
    boolean isActive,
    int stepCount,
    List<AuthFlowStepResponse> steps,
    Instant createdAt,
    Instant updatedAt
) {
    public static AuthFlowResponse from(AuthFlow entity) {
        List<AuthFlowStepResponse> stepResponses = entity.getSteps() != null
            ? entity.getSteps().stream().map(AuthFlowStepResponse::from).toList()
            : List.of();
        return new AuthFlowResponse(
            entity.getId(),
            entity.getTenant().getId(),
            entity.getName(),
            entity.getDescription(),
            entity.getOperationType(),
            entity.isDefault(),
            entity.isActive(),
            entity.getStepCount(),
            stepResponses,
            entity.getCreatedAt(),
            entity.getUpdatedAt()
        );
    }
}
