package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.dto.BiometricVerificationResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;
import java.util.UUID;

/**
 * REST controller for biometric endpoints.
 *
 * Refactored to use Hexagonal Architecture input ports (use cases).
 */
@RestController
@RequestMapping("/api/v1/biometric")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Biometric", description = "Biometric enrollment and verification endpoints")
public class BiometricController {

    private final EnrollBiometricUseCase enrollBiometricUseCase;
    private final VerifyBiometricUseCase verifyBiometricUseCase;
    private final BiometricServicePort biometricServicePort;

    @PostMapping(value = "/enroll/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
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

    @PostMapping(value = "/verify/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
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

    @PostMapping("/fingerprint/enroll/{userId}")
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

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(success)
            .confidence(success ? 1.0 : 0.0)
            .message(success ? "Fingerprint enrolled successfully" : String.valueOf(result.get("message")))
            .build());
    }

    @PostMapping("/fingerprint/verify/{userId}")
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

    @PostMapping("/voice/enroll/{userId}")
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

        return ResponseEntity.ok(BiometricVerificationResponse.builder()
            .verified(success)
            .confidence(success ? 1.0 : 0.0)
            .message(success ? "Voice enrolled successfully" : String.valueOf(result.get("message")))
            .build());
    }

    @PostMapping("/voice/verify/{userId}")
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

    private BiometricVerificationResponse mapToVerificationResponse(BiometricResponse response) {
        return BiometricVerificationResponse.builder()
            .verified(response.isSuccess())
            .confidence(response.getConfidence() != null ? response.getConfidence() : 0.0)
            .message(response.getMessage())
            .build();
    }
}
