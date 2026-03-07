package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.EnrollmentQueryService;
import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.exception.ResourceNotFoundException;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/enrollments")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Enrollments", description = "Biometric enrollment management")
public class EnrollmentController {

    private final EnrollmentQueryService enrollmentQueryService;
    private final UserEnrollmentRepository enrollmentRepository;

    @GetMapping
    @Operation(summary = "Get all enrollments")
    @PreAuthorize("hasPermission(null, 'enrollment', 'read')")
    public ResponseEntity<List<EnrollmentDto>> getAllEnrollments() {
        log.info("GET /api/v1/enrollments");
        return ResponseEntity.ok(enrollmentQueryService.getAllEnrollments());
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get enrollment by ID")
    @PreAuthorize("hasPermission(null, 'enrollment', 'read')")
    public ResponseEntity<EnrollmentDto> getEnrollmentById(@PathVariable String id) {
        log.info("GET /api/v1/enrollments/{}", id);
        return ResponseEntity.ok(enrollmentQueryService.getEnrollmentById(UUID.fromString(id)));
    }

    @PostMapping("/{id}/retry")
    @Operation(summary = "Retry a failed enrollment")
    @PreAuthorize("hasPermission(null, 'enrollment', 'update')")
    public ResponseEntity<EnrollmentDto> retryEnrollment(@PathVariable UUID id) {
        log.info("POST /api/v1/enrollments/{}/retry", id);
        UserEnrollment enrollment = enrollmentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Enrollment not found"));
        if (!"FAILED".equals(enrollment.getStatus().name())) {
            throw new IllegalStateException("Only failed enrollments can be retried");
        }
        enrollment.startEnrollment();
        enrollmentRepository.save(enrollment);
        return ResponseEntity.ok(mapToDto(enrollment));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete an enrollment")
    @PreAuthorize("hasPermission(null, 'enrollment', 'delete')")
    public ResponseEntity<Void> deleteEnrollment(@PathVariable String id) {
        log.info("DELETE /api/v1/enrollments/{}", id);
        enrollmentQueryService.deleteEnrollment(UUID.fromString(id));
        return ResponseEntity.noContent().build();
    }

    private EnrollmentDto mapToDto(UserEnrollment enrollment) {
        return EnrollmentDto.builder()
                .id(enrollment.getId().toString())
                .userId(enrollment.getUser() != null ? enrollment.getUser().getId().toString() : null)
                .userName(enrollment.getUser() != null ? enrollment.getUser().getFullName() : null)
                .userEmail(enrollment.getUser() != null ? enrollment.getUser().getEmail() : null)
                .tenantId(enrollment.getTenant() != null ? enrollment.getTenant().getId().toString() : null)
                .authMethodType(enrollment.getAuthMethodType() != null ? enrollment.getAuthMethodType().name() : null)
                .status(enrollment.getStatus().name())
                .enrolledAt(enrollment.getEnrolledAt())
                .createdAt(enrollment.getCreatedAt())
                .updatedAt(enrollment.getUpdatedAt())
                .completedAt(enrollment.isEnrolled() ? enrollment.getEnrolledAt() : null)
                .build();
    }
}
