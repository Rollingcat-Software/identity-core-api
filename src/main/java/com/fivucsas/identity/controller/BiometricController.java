package com.fivucsas.identity.controller;

import com.fivucsas.identity.dto.BiometricVerificationResponse;
import com.fivucsas.identity.service.BiometricService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/biometric")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Biometric", description = "Biometric enrollment and verification endpoints")
public class BiometricController {

    private final BiometricService biometricService;

    @PostMapping(value = "/enroll/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Enroll user's face biometric data")
    public ResponseEntity<BiometricVerificationResponse> enrollFace(
            @PathVariable UUID userId,
            @RequestParam("image") MultipartFile image) {

        log.info("Face enrollment request for user: {}", userId);
        BiometricVerificationResponse response = biometricService.enrollFace(userId, image);
        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "/verify/{userId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Verify user's face against enrolled biometric data")
    public ResponseEntity<BiometricVerificationResponse> verifyFace(
            @PathVariable UUID userId,
            @RequestParam("image") MultipartFile image) {

        log.info("Face verification request for user: {}", userId);
        BiometricVerificationResponse response = biometricService.verifyFace(userId, image);
        return ResponseEntity.ok(response);
    }
}
