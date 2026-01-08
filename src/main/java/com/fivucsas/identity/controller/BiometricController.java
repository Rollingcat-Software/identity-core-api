package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.EnrollBiometricCommand;
import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
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

    private BiometricVerificationResponse mapToVerificationResponse(BiometricResponse response) {
        return BiometricVerificationResponse.builder()
            .verified(response.isSuccess())
            .confidence(response.getConfidence() != null ? response.getConfidence() : 0.0)
            .message(response.getMessage())
            .build();
    }
}
