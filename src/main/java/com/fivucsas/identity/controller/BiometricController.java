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
import org.springframework.beans.factory.annotation.Value;
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

    // #11 (2026-05-21): cap inbound voice payloads. Previously the voice-enroll
    // path only null/blank-checked voiceData, so an oversized base64 blob would
    // be forwarded straight to the biometric-processor. Mirrors the
    // app.security.max-devices-per-user @Value style in ManageDeviceService.
    // Default 10 MB matches the prod servlet max-file-size in application-prod.yml.
    @Value("${app.security.max-voice-bytes:10485760}")
    private long maxVoiceBytes;

    // Per-user cap on the number of VOICE enrollments. Mirrors max-devices-per-user.
    @Value("${app.security.max-voice-enrollments-per-user:5}")
    private int maxVoiceEnrollmentsPerUser;

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
            @RequestParam("image") MultipartFile image,
            @RequestParam(value = "tenant_id", required = false) String tenantId,
            @RequestParam(value = "client_embedding", required = false) String clientEmbedding,
            @RequestParam(value = "client_embeddings", required = false) String clientEmbeddings) {

        log.info("Face enrollment request for user: {} (tenant: {})", userId, tenantId);

        EnrollBiometricCommand command = EnrollBiometricCommand.builder()
            .userId(userId.toString())
            .faceImage(image)
            .tenantId(tenantId)
            .clientEmbedding(clientEmbedding)
            .clientEmbeddings(clientEmbeddings)
            .build();

        BiometricResponse response = enrollBiometricUseCase.execute(command);

        return ResponseEntity.ok(mapToVerificationResponse(response));
    }

    @PostMapping(value = "/api/v1/biometric/enroll/multi/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Multi-image face enrollment (2-5 images for stronger template)")
    @PreAuthorize("hasAuthority('biometric:enroll') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<Map<String, Object>> enrollFaceMulti(
            @PathVariable UUID userId,
            @RequestParam("files") List<MultipartFile> files,
            @RequestParam(value = "tenant_id", required = false) String tenantId,
            @RequestParam(value = "client_embedding", required = false) String clientEmbedding,
            @RequestParam(value = "client_embeddings", required = false) String clientEmbeddings) {

        log.info("Multi-image face enrollment for user: {}, images: {}, tenant: {}",
                userId, files.size(), tenantId);
        Map<String, Object> result = biometricServicePort.enrollFaceMulti(
                userId, files, tenantId, clientEmbedding, clientEmbeddings);
        recordEnrollmentScores(userId, AuthMethodType.FACE, result);
        return ResponseEntity.ok(result);
    }

    @PostMapping(value = "/api/v1/biometric/verify/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Verify user's face against enrolled biometric data")
    @PreAuthorize("hasAuthority('biometric:verify') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<BiometricVerificationResponse> verifyFace(
            @PathVariable UUID userId,
            @RequestParam("image") MultipartFile image,
            @RequestParam(value = "tenant_id", required = false) String tenantId,
            @RequestParam(value = "client_embedding", required = false) String clientEmbedding,
            @RequestParam(value = "client_embeddings", required = false) String clientEmbeddings) {

        log.info("Face verification request for user: {} (tenant: {})", userId, tenantId);

        VerifyBiometricCommand command = VerifyBiometricCommand.builder()
            .userId(userId.toString())
            .faceImage(image)
            .tenantId(tenantId)
            .clientEmbedding(clientEmbedding)
            .clientEmbeddings(clientEmbeddings)
            .build();

        BiometricResponse response = verifyBiometricUseCase.execute(command);

        return ResponseEntity.ok(mapToVerificationResponse(response));
    }

    // Fingerprint enroll/verify endpoints removed (P1.4): the biometric-processor
    // backend was a SHA-256 hash placeholder, not a real biometric. Platform
    // fingerprint authentication is now provided exclusively via WebAuthn (FIDO2)
    // through FingerprintAuthHandler, which uses the platform authenticator and
    // signed assertions — see /api/v1/auth/mfa/step with method=FINGERPRINT.

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

        // #11 (2026-05-21): reject oversized payloads with a clean 4xx before
        // forwarding to the biometric-processor. We size against the decoded
        // byte length so the limit is independent of base64 inflation.
        long decodedBytes = estimateBase64DecodedLength(voiceData);
        if (decodedBytes > maxVoiceBytes) {
            log.warn("Voice enrollment rejected for user {} — payload {} bytes exceeds cap {} bytes",
                    userId, decodedBytes, maxVoiceBytes);
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(
                BiometricVerificationResponse.builder()
                    .verified(false).confidence(0.0)
                    .message("voiceData exceeds the maximum allowed size").build());
        }

        // Per-user voice-enrollment count cap. getUserEnrollments() is already
        // wired here; counting VOICE rows is trivial. Existing enrollments
        // count toward the limit, so a user at the cap cannot add another.
        long existingVoiceEnrollments = manageEnrollmentUseCase.getUserEnrollments(userId).stream()
                .filter(e -> e.authMethodType() == AuthMethodType.VOICE)
                .count();
        if (existingVoiceEnrollments >= maxVoiceEnrollmentsPerUser) {
            log.warn("Voice enrollment rejected for user {} — {} enrollments at/over cap {}",
                    userId, existingVoiceEnrollments, maxVoiceEnrollmentsPerUser);
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                BiometricVerificationResponse.builder()
                    .verified(false).confidence(0.0)
                    .message("Maximum number of voice enrollments reached").build());
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

    // Fingerprint delete endpoint removed (P1.4): WebAuthn credentials are deleted
    // through ManageEnrollmentService.cleanupMethodData (FINGERPRINT case),
    // which scopes to internal-transport WebAuthn credentials.

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
    public ResponseEntity<Map<String, Object>> searchFace(
            @RequestParam("file") MultipartFile image,
            @RequestParam(value = "client_embedding", required = false) String clientEmbedding,
            @RequestParam(value = "client_embeddings", required = false) String clientEmbeddings) {
        // USER-BUG-4 fix: derive tenant_id from authenticated user, never trust the
        // client. The biometric-processor /search endpoint requires `tenant_id`
        // (Form min_length=1) and the pgvector query enforces `AND tenant_id = $4`.
        // Previously, frontend-initiated calls could omit tenant_id, scoping searches
        // to NULL — which silently filtered out every embedding row whose tenant_id
        // also happens to be NULL (orphan rows from earlier enrollments) AND every
        // properly-scoped row, returning "No matches found" even for enrolled users.
        String tenantId = resolveCurrentTenantId();
        log.info("Face search request (tenant: {})", tenantId);
        Map<String, Object> result = biometricServicePort.searchFace(
                image, tenantId, clientEmbedding, clientEmbeddings);
        return ResponseEntity.ok(result);
    }

    /**
     * Resolves the tenant_id of the currently authenticated principal. Throws
     * 401 when no principal is on the security context (defense-in-depth: the
     * @PreAuthorize("isAuthenticated()") gate already guards this, but we treat
     * a missing user here as a hard auth failure rather than silently passing
     * a null tenant downstream).
     */
    private String resolveCurrentTenantId() {
        // Resolve the principal's tenant via the security-layer helper, which keeps
        // the JPA `entity.User` type contained inside `security..` per the
        // hexagonal-boundary ratchet enforced by UserDomainBoundaryTest.
        UUID tenantId = rbacService.getCurrentUserTenantId()
                .orElseThrow(UnauthorizedException::new);
        return tenantId.toString();
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
            // INVESTIGATION_MASTER_2026-05-07 §wires: forward the bio
            // processor's real distance/threshold so the SPA stops faking
            // distance=1, threshold=0.4 sentinels (BiometricService.ts:218).
            .distance(response.getDistance())
            .threshold(response.getThreshold())
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

    /**
     * Estimates the decoded byte length of a base64 string without allocating
     * the decoded buffer. Tolerates an optional {@code data:...;base64,} prefix
     * and any whitespace/newlines in the payload. Used to enforce the voice
     * payload size cap (#11) before forwarding the blob downstream.
     */
    private static long estimateBase64DecodedLength(String base64) {
        int comma = base64.indexOf(',');
        String body = (base64.startsWith("data:") && comma >= 0)
                ? base64.substring(comma + 1)
                : base64;
        long chars = 0;
        int padding = 0;
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (Character.isWhitespace(c)) {
                continue;
            }
            chars++;
            if (c == '=') {
                padding++;
            }
        }
        // Every 4 base64 chars encode 3 bytes; trailing '=' padding (0-2) trims
        // the final group.
        return (chars / 4) * 3L - padding;
    }
}
