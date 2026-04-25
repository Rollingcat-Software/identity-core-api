package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.BiometricDeviceRequest;
import com.fivucsas.identity.application.dto.command.BiometricVerifyRequest;
import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.command.RegisterStepUpDeviceRequest;
import com.fivucsas.identity.application.dto.command.StepUpChallengeRequest;
import com.fivucsas.identity.application.dto.command.StepUpVerifyRequest;
import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.StepUpChallengeResponse;
import com.fivucsas.identity.application.dto.response.StepUpVerifyResponse;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.input.StepUpAuthUseCase;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.EnrollBiometricService;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import com.fivucsas.identity.dto.BiometricVerificationResponse;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for biometric endpoints.
 *
 * Includes merged endpoints from AuthBiometricController (/api/v1/auth/biometric/*).
 * Uses full path on each method to support two different base paths.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Biometric", description = "Biometric enrollment, verification and device-bound step-up endpoints")
public class BiometricController {

    private final EnrollBiometricUseCase enrollBiometricUseCase;
    private final VerifyBiometricUseCase verifyBiometricUseCase;
    private final BiometricServicePort biometricServicePort;
    private final StepUpAuthUseCase stepUpAuthUseCase;
    private final ManageEnrollmentUseCase manageEnrollmentUseCase;
    private final RbacAuthorizationService rbacService;

    @GetMapping("/api/v1/biometric/health")
    @Operation(summary = "Check biometric processor health via proxy")
    public ResponseEntity<Map<String, Object>> biometricHealth() {
        log.info("Biometric health check request (proxy)");
        try {
            Map<String, Object> result = biometricServicePort.checkHealth();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Biometric health check failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("status", "unhealthy", "error", e.getMessage()));
        }
    }

    @PostMapping(value = "/api/v1/biometric/enroll/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Enroll user's face biometric data")
    @PreAuthorize("hasAuthority('biometric:enroll') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> enrollFace(
            @PathVariable UUID userId,
            @RequestParam("image") MultipartFile image) {

        log.info("Face enrollment request for user: {}", userId);

        EnrollBiometricCommand command = EnrollBiometricCommand.builder()
            .userId(userId.toString())
            .faceImage(image)
            .build();

        BiometricResponse response = enrollBiometricUseCase.execute(command);

        return ResponseEntity.ok(mapToVerificationResponse(response));
    }

    @PostMapping(value = "/api/v1/biometric/enroll/multi/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Multi-image face enrollment (2-5 images for stronger template)")
    @PreAuthorize("hasAuthority('biometric:enroll') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> enrollFaceMulti(
            @PathVariable UUID userId,
            @RequestParam("files") List<MultipartFile> files) {

        log.info("Multi-image face enrollment for user: {}, images: {}", userId, files.size());
        Map<String, Object> result = biometricServicePort.enrollFaceMulti(userId, files);
        recordEnrollmentScores(userId, AuthMethodType.FACE, result);
        return ResponseEntity.ok(result);
    }

    @PostMapping(value = "/api/v1/biometric/verify/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Verify user's face against enrolled biometric data")
    @PreAuthorize("hasAuthority('biometric:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> verifyFace(
            @PathVariable UUID userId,
            @RequestParam("image") MultipartFile image) {

        log.info("Face verification request for user: {}", userId);

        VerifyBiometricCommand command = VerifyBiometricCommand.builder()
            .userId(userId.toString())
            .faceImage(image)
            .build();

        BiometricResponse response = verifyBiometricUseCase.execute(command);

        return ResponseEntity.ok(mapToVerificationResponse(response));
    }

    @PostMapping("/api/v1/biometric/fingerprint/enroll/{userId}")
    @Operation(summary = "Enroll user's fingerprint biometric data")
    @PreAuthorize("hasAuthority('biometric:enroll') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> enrollFingerprint(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {

        log.info("Fingerprint enrollment request for user: {}", userId);

        String fingerprintData = request.get("fingerprintData");
        if (fingerprintData == null || fingerprintData.isBlank()) {
            return ResponseEntity.badRequest().body(
                BiometricVerificationResponse.builder()
                    .verified(false).confidence(0.0)
                    .message("fingerprintData is required").build());
        }

        Map<String, Object> result = biometricServicePort.enrollFingerprint(userId, fingerprintData);
        boolean success = Boolean.TRUE.equals(result.get("success"))
                || "true".equalsIgnoreCase(String.valueOf(result.get("success")));

        if (success) {
            recordEnrollmentScores(userId, AuthMethodType.FINGERPRINT, result);
        }

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(success)
            .confidence(success ? 1.0 : 0.0)
            .message(success ? "Fingerprint enrolled successfully" : String.valueOf(result.get("message")))
            .build());
    }

    @PostMapping("/api/v1/biometric/fingerprint/verify/{userId}")
    @Operation(summary = "Verify user's fingerprint against enrolled biometric data")
    @PreAuthorize("hasAuthority('biometric:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> verifyFingerprint(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {

        log.info("Fingerprint verification request for user: {}", userId);

        String fingerprintData = request.get("fingerprintData");
        if (fingerprintData == null || fingerprintData.isBlank()) {
            return ResponseEntity.badRequest().body(
                BiometricVerificationResponse.builder()
                    .verified(false).confidence(0.0)
                    .message("fingerprintData is required").build());
        }

        Map<String, Object> result = biometricServicePort.verifyFingerprint(userId, fingerprintData);
        boolean verified = Boolean.TRUE.equals(result.get("verified"))
                || "true".equalsIgnoreCase(String.valueOf(result.get("verified")));

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(verified)
            .confidence(verified ? 1.0 : 0.0)
            .message(verified ? "Fingerprint verified successfully" : "Fingerprint verification failed")
            .build());
    }

    @PostMapping("/api/v1/biometric/voice/enroll/{userId}")
    @Operation(summary = "Enroll user's voice biometric data")
    @PreAuthorize("hasAuthority('biometric:enroll') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> enrollVoice(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {

        log.info("Voice enrollment request for user: {}", userId);

        String voiceData = request.get("voiceData");
        if (voiceData == null || voiceData.isBlank()) {
            return ResponseEntity.badRequest().body(
                BiometricVerificationResponse.builder()
                    .verified(false).confidence(0.0)
                    .message("voiceData is required").build());
        }

        Map<String, Object> result = biometricServicePort.enrollVoice(userId, voiceData);
        boolean success = Boolean.TRUE.equals(result.get("success"))
                || "true".equalsIgnoreCase(String.valueOf(result.get("success")));

        if (success) {
            recordEnrollmentScores(userId, AuthMethodType.VOICE, result);
        }

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(success)
            .confidence(success ? 1.0 : 0.0)
            .message(success ? "Voice enrolled successfully" : String.valueOf(result.get("message")))
            .build());
    }

    @PostMapping("/api/v1/biometric/voice/verify/{userId}")
    @Operation(summary = "Verify user's voice against enrolled biometric data")
    @PreAuthorize("hasAuthority('biometric:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> verifyVoice(
            @PathVariable UUID userId,
            @RequestBody Map<String, String> request) {

        log.info("Voice verification request for user: {}", userId);

        String voiceData = request.get("voiceData");
        if (voiceData == null || voiceData.isBlank()) {
            return ResponseEntity.badRequest().body(
                BiometricVerificationResponse.builder()
                    .verified(false).confidence(0.0)
                    .message("voiceData is required").build());
        }

        Map<String, Object> result = biometricServicePort.verifyVoice(userId, voiceData);
        boolean verified = Boolean.TRUE.equals(result.get("verified"))
                || "true".equalsIgnoreCase(String.valueOf(result.get("verified")));

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(verified)
            .confidence(verified ? 1.0 : 0.0)
            .message(verified ? "Voice verified successfully" : "Voice verification failed")
            .build());
    }

    @DeleteMapping("/api/v1/biometric/face/{userId}")
    @Operation(summary = "Delete user's enrolled face biometric data")
    @PreAuthorize("hasAuthority('biometric:delete') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> deleteFace(@PathVariable UUID userId) {
        log.info("Face deletion request for user: {}", userId);

        Map<String, Object> result = biometricServicePort.deleteFace(userId);
        boolean success = Boolean.TRUE.equals(result.get("success"))
                || "true".equalsIgnoreCase(String.valueOf(result.get("success")));

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(success)
            .confidence(0.0)
            .message(success ? "Face data deleted successfully" : String.valueOf(result.get("message")))
            .build());
    }

    @DeleteMapping("/api/v1/biometric/fingerprint/{userId}")
    @Operation(summary = "Delete user's enrolled fingerprint biometric data")
    @PreAuthorize("hasAuthority('biometric:delete') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> deleteFingerprint(@PathVariable UUID userId) {
        log.info("Fingerprint deletion request for user: {}", userId);

        Map<String, Object> result = biometricServicePort.deleteFingerprint(userId);
        boolean success = Boolean.TRUE.equals(result.get("success"))
                || "true".equalsIgnoreCase(String.valueOf(result.get("success")));

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(success)
            .confidence(0.0)
            .message(success ? "Fingerprint data deleted successfully" : String.valueOf(result.get("message")))
            .build());
    }

    @DeleteMapping("/api/v1/biometric/voice/{userId}")
    @Operation(summary = "Delete user's enrolled voice biometric data")
    @PreAuthorize("hasAuthority('biometric:delete') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> deleteVoice(@PathVariable UUID userId) {
        log.info("Voice deletion request for user: {}", userId);

        Map<String, Object> result = biometricServicePort.deleteVoice(userId);
        boolean success = Boolean.TRUE.equals(result.get("success"))
                || "true".equalsIgnoreCase(String.valueOf(result.get("success")));

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(success)
            .confidence(0.0)
            .message(success ? "Voice data deleted successfully" : String.valueOf(result.get("message")))
            .build());
    }

    @PostMapping(value = "/api/v1/biometric/search", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Search for a face in enrolled database (1:N identification)")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> searchFace(@RequestParam("file") MultipartFile image) {
        log.info("Face search request");
        Map<String, Object> result = biometricServicePort.searchFace(image);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/api/v1/biometric/voice/search")
    @Operation(summary = "Search for a speaker in enrolled database (1:N voice identification)")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> searchVoice(@RequestBody Map<String, String> body) {
        log.info("Voice search request");
        String voiceData = body.get("voiceData");
        if (voiceData == null || voiceData.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "voiceData is required"));
        }
        Map<String, Object> result = biometricServicePort.searchVoice(voiceData);
        return ResponseEntity.ok(result);
    }

    @PostMapping(value = "/api/v1/biometric/card-detect", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Detect card type from image (Turkish ID, passport, driver's license, etc.)")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> detectCardType(@RequestParam("file") MultipartFile image) {
        log.info("Card type detection request");
        Map<String, Object> result = biometricServicePort.detectCardType(image);
        return ResponseEntity.ok(result);
    }

    // --- Auth Biometric (device-bound step-up) endpoints merged from AuthBiometricController ---

    @PostMapping("/api/v1/auth/biometric/devices")
    @Operation(summary = "Register a biometric device for step-up authentication")
    public ResponseEntity<DeviceResponse> registerAuthDevice(@Valid @RequestBody BiometricDeviceRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        DevicePlatform devicePlatform;
        try {
            devicePlatform = DevicePlatform.valueOf(request.platform().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid platform: '" + request.platform() + "'. Allowed values: WEB, ANDROID, IOS, DESKTOP");
        }

        RegisterStepUpDeviceRequest stepUpRequest = new RegisterStepUpDeviceRequest(
                request.keyId(),
                devicePlatform,
                request.publicKeyJwk(),
                "ECDSA-P256",
                null,
                List.of("biometric")
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(stepUpAuthUseCase.registerStepUpDevice(
                        currentUser.getId(), currentUser.getTenant().getId(), stepUpRequest));
    }

    @PostMapping("/api/v1/auth/biometric/challenge")
    @Operation(summary = "Request a challenge nonce for biometric verification")
    public ResponseEntity<Map<String, Object>> createAuthChallenge() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        StepUpChallengeRequest challengeRequest = new StepUpChallengeRequest("default");
        StepUpChallengeResponse response = stepUpAuthUseCase.requestChallenge(
                currentUser.getId(), challengeRequest);

        return ResponseEntity.ok(Map.of(
                "challengeId", response.challenge(),
                "nonce", response.challenge()
        ));
    }

    @PostMapping("/api/v1/auth/biometric/verify")
    @Operation(summary = "Verify a signed biometric challenge")
    public ResponseEntity<Map<String, Object>> verifyAuthSignature(@Valid @RequestBody BiometricVerifyRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new UnauthorizedException());

        StepUpVerifyRequest verifyRequest = new StepUpVerifyRequest(
                request.keyId(),
                request.challengeId(),
                request.signatureBase64()
        );

        StepUpVerifyResponse response = stepUpAuthUseCase.verifyChallenge(
                currentUser.getId(), verifyRequest);

        return ResponseEntity.ok(Map.of(
                "stepUpToken", response.accessToken() != null ? response.accessToken() : "",
                "verified", response.verified()
        ));
    }

    private BiometricVerificationResponse mapToVerificationResponse(BiometricResponse response) {
        return BiometricVerificationResponse.builder()
            .verified(response.isSuccess())
            .confidence(response.getConfidence() != null ? response.getConfidence() : 0.0)
            .message(response.getMessage())
            .build();
    }

    /**
     * Best-effort: extract quality + liveness scores from the biometric-processor
     * response and persist them on the matching user_enrollments row. Wrapped
     * defensively so the upload itself never fails because of admin bookkeeping.
     */
    private void recordEnrollmentScores(UUID userId, AuthMethodType methodType, Map<String, Object> response) {
        try {
            BigDecimal quality = EnrollBiometricService.extractScore(response, "quality_score");
            BigDecimal liveness = EnrollBiometricService.extractScore(response, "liveness_score");
            manageEnrollmentUseCase.recordBiometricScores(userId, methodType, quality, liveness);
        } catch (Exception e) {
            log.warn("Failed to persist enrollment scores for user {} method {}: {}",
                    userId, methodType, e.getMessage());
        }
    }
}
