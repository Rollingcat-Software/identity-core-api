package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.EnrollmentQueryService;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.exception.ResourceNotFoundException;
import com.fivucsas.identity.repository.BiometricDataRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for enrollment management.
 *
 * Merges: EnrollmentController + EnrollmentManagementController + UserEnrollmentFlowController
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Enrollments", description = "Biometric enrollment management")
public class EnrollmentController {

    private final EnrollmentQueryService enrollmentQueryService;
    private final UserEnrollmentRepository enrollmentRepository;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;
    private final BiometricServicePort biometricService;
    private final BiometricDataRepository biometricDataRepository;
    private final RbacAuthorizationService rbacService;

    // --- /api/v1/enrollments endpoints ---

    @GetMapping("/api/v1/enrollments")
    @Operation(summary = "Get all enrollments")
    @PreAuthorize("hasPermission(null, 'enrollment', 'read')")
    public ResponseEntity<List<EnrollmentDto>> getAllEnrollments() {
        log.info("GET /api/v1/enrollments");
        return ResponseEntity.ok(enrollmentQueryService.getAllEnrollments());
    }

    @GetMapping("/api/v1/enrollments/{id}")
    @Operation(summary = "Get enrollment by ID")
    @PreAuthorize("hasPermission(null, 'enrollment', 'read')")
    public ResponseEntity<EnrollmentDto> getEnrollmentById(@PathVariable String id) {
        log.info("GET /api/v1/enrollments/{}", id);
        return ResponseEntity.ok(enrollmentQueryService.getEnrollmentById(UUID.fromString(id)));
    }

    @PostMapping("/api/v1/enrollments/{id}/retry")
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

    @DeleteMapping("/api/v1/enrollments/{id}")
    @Operation(summary = "Delete an enrollment")
    @PreAuthorize("hasPermission(null, 'enrollment', 'delete')")
    public ResponseEntity<Void> deleteEnrollment(@PathVariable String id) {
        log.info("DELETE /api/v1/enrollments/{}", id);
        enrollmentQueryService.deleteEnrollment(UUID.fromString(id));
        return ResponseEntity.noContent().build();
    }

    // --- /api/v1/users/{userId}/enrollments endpoints (from EnrollmentManagementController) ---

    @GetMapping("/api/v1/users/{userId}/enrollments")
    @PreAuthorize("hasPermission(#userId, 'User', 'enrollment:read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<List<EnrollmentResponse>> getUserEnrollments(@PathVariable UUID userId) {
        return ResponseEntity.ok(manageEnrollmentUseCase.getUserEnrollments(userId));
    }

    @PostMapping("/api/v1/users/{userId}/enrollments")
    @PreAuthorize("hasPermission(#userId, 'User', 'enrollment:create') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<EnrollmentResponse> startEnrollment(
            @PathVariable UUID userId,
            @RequestParam UUID tenantId,
            @RequestParam AuthMethodType methodType) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(manageEnrollmentUseCase.startEnrollment(userId, tenantId, methodType));
    }

    @DeleteMapping("/api/v1/users/{userId}/enrollments/{methodType}")
    @PreAuthorize("hasPermission(#userId, 'User', 'enrollment:delete') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Void> revokeEnrollment(
            @PathVariable UUID userId,
            @PathVariable AuthMethodType methodType) {
        manageEnrollmentUseCase.revokeEnrollment(userId, methodType);
        return ResponseEntity.noContent().build();
    }

    // --- /api/v1/enrollment endpoints (from UserEnrollmentFlowController) ---

    @PostMapping(value = "/api/v1/enrollment/submit", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Submit enrollment with face image and identity information")
    public ResponseEntity<Map<String, Object>> submitEnrollment(
            @RequestParam("nationalId") String nationalId,
            @RequestParam("dateOfBirth") String dateOfBirth,
            @RequestParam("fullName") String fullName,
            @RequestParam("livenessToken") String livenessToken,
            @RequestParam("livenessScore") String livenessScore,
            @RequestPart("faceImage") MultipartFile faceImage) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        log.info("Enrollment submission for user: {}, nationalId: {}", currentUser.getId(), nationalId);

        Map<String, Object> enrollResult = biometricService.enrollFace(currentUser.getId(), faceImage);

        boolean success = Boolean.TRUE.equals(enrollResult.get("success"));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", success ? "COMPLETED" : "FAILED");
        response.put("qualityScore", enrollResult.getOrDefault("quality_score", 0.0));
        response.put("livenessScore", parseDouble(livenessScore));
        response.put("message", enrollResult.getOrDefault("message", ""));
        response.put("errorMessage", success ? null : enrollResult.getOrDefault("message", "Enrollment failed"));

        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/v1/enrollment/status")
    @Operation(summary = "Get current user's enrollment status")
    public ResponseEntity<Map<String, Object>> getEnrollmentStatus() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        boolean enrolled = biometricDataRepository.findByUserId(currentUser.getId()).isPresent();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", enrolled ? "COMPLETED" : "NOT_STARTED");
        response.put("qualityScore", enrolled ? 85.0 : null);
        response.put("livenessScore", enrolled ? 1.0 : null);
        response.put("errorMessage", null);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/api/v1/enrollment/liveness/challenge")
    @Operation(summary = "Request a liveness challenge for enrollment verification")
    public ResponseEntity<Map<String, Object>> requestLivenessChallenge(
            @RequestBody(required = false) Map<String, Object> body) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        log.info("Liveness challenge requested for user: {}", currentUser.getId());

        Map<String, Object> puzzleResult = biometricService.generateLivenessPuzzle(
                currentUser.getId().toString(), "standard");

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("challengeId", puzzleResult.getOrDefault("puzzle_id", ""));
        response.put("instruction", "Please follow the on-screen instructions");
        response.put("steps", puzzleResult.getOrDefault("steps", List.of()));
        response.put("timeoutSeconds", puzzleResult.getOrDefault("timeout_seconds", 60));

        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "/api/v1/enrollment/liveness/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Verify liveness challenge with captured frames")
    public ResponseEntity<Map<String, Object>> verifyLiveness(
            @RequestParam("challengeId") String challengeId,
            @RequestPart("frame_0") MultipartFile frame0,
            @RequestPart(value = "frame_1", required = false) MultipartFile frame1,
            @RequestPart(value = "frame_2", required = false) MultipartFile frame2) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        log.info("Liveness verification for user: {}, challengeId: {}", currentUser.getId(), challengeId);

        List<MultipartFile> frames = new ArrayList<>();
        frames.add(frame0);
        if (frame1 != null) frames.add(frame1);
        if (frame2 != null) frames.add(frame2);

        Map<String, Object> verifyResult = biometricService.verifyLivenessPuzzle(challengeId, frames);

        boolean passed = Boolean.TRUE.equals(verifyResult.get("success"))
                || Boolean.TRUE.equals(verifyResult.get("liveness_confirmed"));
        double score = verifyResult.containsKey("overall_score")
                ? ((Number) verifyResult.get("overall_score")).doubleValue() / 100.0
                : (passed ? 0.95 : 0.0);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("passed", passed);
        response.put("score", score);
        response.put("token", challengeId);

        return ResponseEntity.ok(response);
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

    private double parseDouble(String value) {
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return 0.0;
        }
    }
}
