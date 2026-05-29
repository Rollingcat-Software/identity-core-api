package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.entity.UserEnrollment;
import jakarta.persistence.EntityNotFoundException;
import org.hibernate.Hibernate;

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
        // P1-4 soft-delete / lazy-proxy guard. An enrollment can outlive its
        // user row (soft-deleted owner — @SQLRestriction hides it, so the lazy
        // proxy throws EntityNotFoundException on field access). Mirror
        // EnrollmentQueryService.mapEnrollmentToDto: force-init the proxy in a
        // try/catch and render null name/email instead of 500-ing the row.
        // The raw user_id FK is still surfaced (read off the join column, which
        // never initializes the proxy) so the row stays identifiable.
        boolean userResolvable = entity.getUser() != null;
        if (userResolvable) {
            try {
                // Hibernate.initialize() loads the proxy and itself throws
                // EntityNotFoundException for a soft-deleted/missing user row —
                // no need for an extra field probe (keeps the entity.User method
                // surface minimal for the UserDomainBoundaryTest ratchet).
                Hibernate.initialize(entity.getUser());
            } catch (EntityNotFoundException ex) {
                userResolvable = false;
            }
        }
        return new EnrollmentResponse(
            entity.getId(),
            entity.getAuthMethodType(),
            entity.getStatus(),
            entity.getEnrolledAt(),
            entity.getExpiresAt(),
            entity.getCreatedAt(),
            entity.getUserId() != null ? entity.getUserId().toString() : null,
            userResolvable ? entity.getUser().getFullName() : null,
            userResolvable ? entity.getUser().getEmail() : null,
            entity.getTenant() != null ? entity.getTenant().getId().toString() : null,
            entity.getQualityScore() != null ? entity.getQualityScore().doubleValue() : null,
            entity.getLivenessScore() != null ? entity.getLivenessScore().doubleValue() : null,
            null, // errorCode
            null, // errorMessage
            entity.getStatus() == EnrollmentStatus.ENROLLED ? entity.getEnrolledAt() : null
        );
    }
}
