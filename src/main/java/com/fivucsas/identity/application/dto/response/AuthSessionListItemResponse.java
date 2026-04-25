package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthSession;

import java.time.Instant;
import java.util.UUID;

/**
 * Admin-list view of an {@link AuthSession}.
 *
 * <p>Deliberately exposes only safe fields. No tokens, no MFA codes, no step
 * payloads — just the metadata an operator needs to triage active or recent
 * authentication attempts (id, user, status, progress, timing, client info).
 * </p>
 *
 * <p>Returned by {@code GET /api/v1/auth/sessions} (admin list endpoint).</p>
 */
public record AuthSessionListItemResponse(
    UUID id,
    UUID userId,
    UUID tenantId,
    OperationType operationType,
    AuthSessionStatus status,
    int currentStep,
    int totalSteps,
    Instant createdAt,
    Instant expiresAt,
    Instant completedAt,
    String ipAddress,
    String userAgent
) {
    public static AuthSessionListItemResponse from(AuthSession session) {
        int totalSteps = session.getAuthFlow() != null ? session.getAuthFlow().getStepCount() : 0;
        UUID userId = session.getUser() != null ? session.getUser().getId() : null;
        UUID tenantId = session.getTenant() != null ? session.getTenant().getId() : null;
        return new AuthSessionListItemResponse(
            session.getId(),
            userId,
            tenantId,
            session.getOperationType(),
            session.getStatus(),
            session.getCurrentStepOrder(),
            totalSteps,
            session.getStartedAt(),
            session.getExpiresAt(),
            session.getCompletedAt(),
            session.getIpAddress(),
            session.getUserAgent()
        );
    }
}
