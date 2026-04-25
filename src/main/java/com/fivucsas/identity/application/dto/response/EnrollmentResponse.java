package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.entity.UserEnrollment;

import java.time.Instant;
import java.util.UUID;

public record EnrollmentResponse(
    UUID id,
    AuthMethodType authMethodType,
    EnrollmentStatus status,
    Instant enrolledAt,
    Instant expiresAt,
    Instant createdAt,
    String userId,
    String userName,
    String userEmail,
    String tenantId,
    Double qualityScore,
    Double livenessScore,
    String errorCode,
    String errorMessage,
    Instant completedAt
) {
    public static EnrollmentResponse from(UserEnrollment entity) {
        return new EnrollmentResponse(
            entity.getId(),
            entity.getAuthMethodType(),
            entity.getStatus(),
            entity.getEnrolledAt(),
            entity.getExpiresAt(),
            entity.getCreatedAt(),
            entity.getUser() != null ? entity.getUser().getId().toString() : null,
            entity.getUser() != null ? entity.getUser().getFullName() : null,
            entity.getUser() != null ? entity.getUser().getEmail() : null,
            entity.getTenant() != null ? entity.getTenant().getId().toString() : null,
            entity.getQualityScore() != null ? entity.getQualityScore().doubleValue() : null,
            entity.getLivenessScore() != null ? entity.getLivenessScore().doubleValue() : null,
            null, // errorCode
            null, // errorMessage
            entity.getStatus() == EnrollmentStatus.ENROLLED ? entity.getEnrolledAt() : null
        );
    }
}
