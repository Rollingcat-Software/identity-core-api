package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthSession;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AuthSessionResponse(
    UUID sessionId,
    AuthSessionStatus status,
    OperationType operationType,
    int currentStepOrder,
    int totalSteps,
    Instant expiresAt,
    List<SessionStepSummary> steps
) {
    public record SessionStepSummary(
        int stepOrder,
        String methodType,
        String status,
        boolean isRequired,
        boolean delegated
    ) {}

    public static AuthSessionResponse from(AuthSession session) {
        List<SessionStepSummary> stepSummaries = session.getSessionSteps() != null
            ? session.getSessionSteps().stream()
                .map(s -> new SessionStepSummary(
                    s.getAuthFlowStep().getStepOrder(),
                    s.getMethodType().name(),
                    s.getStatus().name(),
                    s.getAuthFlowStep().isRequired(),
                    s.isDelegated()
                ))
                .toList()
            : List.of();

        return new AuthSessionResponse(
            session.getId(),
            session.getStatus(),
            session.getOperationType(),
            session.getCurrentStepOrder(),
            session.getAuthFlow().getStepCount(),
            session.getExpiresAt(),
            stepSummaries
        );
    }
}
