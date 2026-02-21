package com.fivucsas.identity.controller;

import com.fivucsas.identity.dto.BiometricChallengeResponse;
import com.fivucsas.identity.dto.BiometricRegisterDeviceRequest;
import com.fivucsas.identity.dto.BiometricRegisterDeviceResponse;
import com.fivucsas.identity.dto.BiometricStepUpTokenResponse;
import com.fivucsas.identity.dto.BiometricVerifyChallengeRequest;
import com.fivucsas.identity.service.BiometricStepUpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Legacy aliases for biometric step-up endpoints.
 *
 * Kept for backwards compatibility with older mobile clients.
 */
@RestController
@RequestMapping("/api/v1/step-up")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Auth Biometric Step-Up (Legacy)", description = "Legacy aliases for biometric step-up endpoints")
public class LegacyBiometricStepUpController {

    private final BiometricStepUpService biometricStepUpService;

    @PostMapping("/register-device")
    @Operation(
            summary = "Legacy alias: register biometric device",
            description = "Legacy alias for POST /api/v1/auth/biometric/devices",
            security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<BiometricRegisterDeviceResponse> registerDevice(
            @Valid @RequestBody BiometricRegisterDeviceRequest request,
            Authentication authentication
    ) {
        String deviceId = biometricStepUpService.registerDevice(authentication.getName(), request);
        return ResponseEntity.ok(BiometricRegisterDeviceResponse.builder().deviceId(deviceId).build());
    }

    @PostMapping("/challenge")
    @Operation(
            summary = "Legacy alias: create one-time biometric challenge",
            description = "Legacy alias for POST /api/v1/auth/biometric/challenge",
            security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<BiometricChallengeResponse> createChallenge(Authentication authentication) {
        return ResponseEntity.ok(biometricStepUpService.createChallenge(authentication.getName()));
    }

    @PostMapping("/verify")
    @Operation(
            summary = "Legacy alias: verify biometric challenge",
            description = "Legacy alias for POST /api/v1/auth/biometric/verify",
            security = @SecurityRequirement(name = "bearer-jwt")
    )
    public ResponseEntity<BiometricStepUpTokenResponse> verifyChallenge(
            @Valid @RequestBody BiometricVerifyChallengeRequest request,
            Authentication authentication
    ) {
        BiometricStepUpTokenResponse response = biometricStepUpService.verifyChallenge(authentication.getName(), request);
        return ResponseEntity.ok(response);
    }
}
