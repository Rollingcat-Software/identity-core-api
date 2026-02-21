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
    Instant createdAt
) {
    public static EnrollmentResponse from(UserEnrollment entity) {
        return new EnrollmentResponse(
            entity.getId(),
            entity.getAuthMethodType(),
            entity.getStatus(),
            entity.getEnrolledAt(),
            entity.getExpiresAt(),
            entity.getCreatedAt()
        );
    }
}
