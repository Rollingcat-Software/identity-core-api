package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RegisterStepUpDeviceRequest;
import com.fivucsas.identity.application.dto.command.StepUpChallengeRequest;
import com.fivucsas.identity.application.dto.command.StepUpVerifyRequest;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.StepUpChallengeResponse;
import com.fivucsas.identity.application.dto.response.StepUpVerifyResponse;
import com.fivucsas.identity.application.port.input.StepUpAuthUseCase;
import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Auth biometric controller providing client-facing endpoints
 * for device-bound biometric step-up authentication.
 *
 * Maps client-apps endpoints (auth/biometric/*) to existing
 * StepUpAuthUseCase implementation.
 */
@RestController
@RequestMapping("/api/v1/auth/biometric")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Auth Biometric", description = "Device-bound biometric authentication for mobile/desktop clients")
public class AuthBiometricController {

    private final StepUpAuthUseCase stepUpAuthUseCase;
    private final RbacAuthorizationService rbacService;

    /**
     * Client request DTO for device registration.
     * Maps client field names to internal StepUpDeviceRequest.
     */
    public record BiometricDeviceRequest(
        @NotBlank String keyId,
        @NotBlank String platform,
        @NotBlank String publicKeyJwk
    ) {}

    /**
     * Client request DTO for challenge verification.
     * Maps client field names to internal StepUpVerifyRequest.
     */
    public record BiometricVerifyRequest(
        @NotBlank String challengeId,
        @NotBlank String keyId,
        @NotBlank String signatureBase64
    ) {}

    @PostMapping("/devices")
    @Operation(summary = "Register a biometric device for step-up authentication")
    public ResponseEntity<DeviceResponse> registerDevice(@Valid @RequestBody BiometricDeviceRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        DevicePlatform devicePlatform;
        try {
            devicePlatform = DevicePlatform.valueOf(request.platform().toUpperCase());
        } catch (IllegalArgumentException e) {
            devicePlatform = DevicePlatform.ANDROID;
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

    @PostMapping("/challenge")
    @Operation(summary = "Request a challenge nonce for biometric verification")
    public ResponseEntity<Map<String, Object>> createChallenge() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

        StepUpChallengeRequest challengeRequest = new StepUpChallengeRequest("default");
        StepUpChallengeResponse response = stepUpAuthUseCase.requestChallenge(
                currentUser.getId(), challengeRequest);

        return ResponseEntity.ok(Map.of(
                "challengeId", response.challenge(),
                "nonce", response.challenge()
        ));
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify a signed biometric challenge")
    public ResponseEntity<Map<String, Object>> verifySignature(@Valid @RequestBody BiometricVerifyRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));

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
}
