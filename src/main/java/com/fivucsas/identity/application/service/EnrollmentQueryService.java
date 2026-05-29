package com.fivucsas.identity.application.service;

import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.exception.ResourceNotFoundException;
import com.fivucsas.identity.application.port.output.UserEnrollmentRepositoryPort;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Hibernate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Application service for enrollment query operations.
 *
 * <p>Reads {@code user_enrollments} as the single source of truth. The legacy
 * {@code biometric_data} table was empty in production for the entire lifetime
 * of the new pipeline (biometric-processor pgvector + user_enrollments scores)
 * and was dropped by V48; the previous fallback path that read from it has
 * therefore been removed.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class EnrollmentQueryService {

    private final UserEnrollmentRepositoryPort userEnrollmentRepository;

    public List<EnrollmentDto> getAllEnrollments() {
        return getAllEnrollments(null);
    }

    /**
     * Returns all enrollments, optionally restricted to a tenant.
     *
     * @param tenantScopeId the tenant to scope by; {@code null} means
     *                      "no scope restriction" (SUPER_ADMIN).
     */
    public List<EnrollmentDto> getAllEnrollments(UUID tenantScopeId) {
        return (tenantScopeId == null
                ? userEnrollmentRepository.findAll()
                : userEnrollmentRepository.findAllByTenantId(tenantScopeId)
        ).stream()
                .map(this::mapEnrollmentToDto)
                .toList();
    }

    public EnrollmentDto getEnrollmentById(UUID id) {
        return userEnrollmentRepository.findById(id)
                .map(this::mapEnrollmentToDto)
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found: " + id));
    }

    @Transactional
    public void deleteEnrollment(UUID id) {
        if (!userEnrollmentRepository.existsById(id)) {
            throw new ResourceNotFoundException("Enrollment not found: " + id);
        }
        userEnrollmentRepository.deleteById(id);
        log.info("UserEnrollment deleted: {}", id);
    }

    private EnrollmentDto mapEnrollmentToDto(UserEnrollment enrollment) {
        // Resolve the associated user defensively. An enrollment can outlive its
        // user row (orphaned FK from a hard-deleted/missing user — observed in
        // prod 2026-05-29: EntityNotFoundException blew up the WHOLE list with a
        // 500). Touching a lazy proxy that points at a missing row throws, so we
        // catch it and render the row with null user fields instead of failing
        // the entire enrollments page.
        var resolved = enrollment.getUser();
        if (resolved != null) {
            try {
                // Force proxy initialization so a missing row surfaces here,
                // where we can swallow it, instead of during DTO field access.
                Hibernate.initialize(resolved);
                resolved.getEmail();
            } catch (EntityNotFoundException ex) {
                log.warn("Enrollment {} references a missing user row; rendering with null user fields",
                        enrollment.getId());
                resolved = null;
            }
        }
        final var user = resolved;
        return EnrollmentDto.builder()
                .id(enrollment.getId().toString())
                .userId(user != null ? user.getId().toString() : null)
                .userName(user != null ? user.getFullName() : null)
                .userEmail(user != null ? user.getEmail() : null)
                .tenantId(enrollment.getTenant() != null ? enrollment.getTenant().getId().toString() : null)
                .authMethodType(enrollment.getAuthMethodType() != null ? enrollment.getAuthMethodType().name() : null)
                .status(enrollment.getStatus().name())
                .enrolledAt(enrollment.getEnrolledAt())
                .createdAt(enrollment.getCreatedAt())
                .updatedAt(enrollment.getUpdatedAt())
                .qualityScore(enrollment.getQualityScore() != null ? enrollment.getQualityScore().doubleValue() : null)
                .livenessScore(enrollment.getLivenessScore() != null ? enrollment.getLivenessScore().doubleValue() : null)
                .completedAt(enrollment.isEnrolled() ? enrollment.getEnrolledAt() : null)
                .build();
    }
}
