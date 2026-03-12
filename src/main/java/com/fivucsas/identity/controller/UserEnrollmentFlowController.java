package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.BiometricDataRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller for the user enrollment flow used by the web-app.
 *
 * Provides endpoints for:
 * - Submitting enrollment with face image and ID info
 * - Checking enrollment status
 * - Liveness challenge-response flow (proxied to biometric-processor)
 */
@RestController
@RequestMapping("/api/v1/enrollment")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Enrollment Flow", description = "User-facing enrollment flow with liveness verification")
public class UserEnrollmentFlowController {

    private final BiometricServicePort biometricService;
    private final BiometricDataRepository biometricDataRepository;
    private final RbacAuthorizationService rbacService;

    @PostMapping(value = "/submit", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Submit enrollment with face image and identity information")
    public ResponseEntity<Map<String, Object>> submitEnrollment(
            @RequestParam("nationalId") String nationalId,
            @RequestParam("dateOfBirth") String dateOfBirth,
            @RequestParam("fullName") String fullName,
            @RequestParam("livenessToken") String livenessToken,
            @RequestParam("livenessScore") String livenessScore,
            @RequestPart("faceImage") MultipartFile faceImage) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

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

    @GetMapping("/status")
    @Operation(summary = "Get current user's enrollment status")
    public ResponseEntity<Map<String, Object>> getEnrollmentStatus() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        boolean enrolled = biometricDataRepository.findByUserId(currentUser.getId()).isPresent();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", enrolled ? "COMPLETED" : "NOT_STARTED");
        response.put("qualityScore", enrolled ? 85.0 : null);
        response.put("livenessScore", enrolled ? 1.0 : null);
        response.put("errorMessage", null);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/liveness/challenge")
    @Operation(summary = "Request a liveness challenge for enrollment verification")
    public ResponseEntity<Map<String, Object>> requestLivenessChallenge(
            @RequestBody(required = false) Map<String, Object> body) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

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

    @PostMapping(value = "/liveness/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Verify liveness challenge with captured frames")
    public ResponseEntity<Map<String, Object>> verifyLiveness(
            @RequestParam("challengeId") String challengeId,
            @RequestPart("frame_0") MultipartFile frame0,
            @RequestPart(value = "frame_1", required = false) MultipartFile frame1,
            @RequestPart(value = "frame_2", required = false) MultipartFile frame2) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        log.info("Liveness verification for user: {}, challengeId: {}", currentUser.getId(), challengeId);

        List<MultipartFile> frames = new java.util.ArrayList<>();
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

    private double parseDouble(String value) {
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return 0.0;
        }
    }
}
