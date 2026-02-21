package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RegisterStepUpDeviceRequest;
import com.fivucsas.identity.application.dto.command.StepUpChallengeRequest;
import com.fivucsas.identity.application.dto.command.StepUpVerifyRequest;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.StepUpChallengeResponse;
import com.fivucsas.identity.application.dto.response.StepUpVerifyResponse;
import com.fivucsas.identity.application.port.input.StepUpAuthUseCase;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/step-up")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Step-Up Authentication", description = "Device-bound biometric step-up authentication (ECDSA P-256)")
public class StepUpController {

    private final StepUpAuthUseCase stepUpAuthUseCase;
    private final RbacAuthorizationService rbacService;

    @PostMapping("/register-device")
    @Operation(summary = "Register device public key for step-up auth")
    public ResponseEntity<DeviceResponse> registerDevice(@Valid @RequestBody RegisterStepUpDeviceRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(stepUpAuthUseCase.registerStepUpDevice(
                        currentUser.getId(), currentUser.getTenant().getId(), request));
    }

    @PostMapping("/challenge")
    @Operation(summary = "Request a challenge nonce for step-up verification")
    public ResponseEntity<StepUpChallengeResponse> requestChallenge(
            @Valid @RequestBody StepUpChallengeRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        return ResponseEntity.ok(stepUpAuthUseCase.requestChallenge(currentUser.getId(), request));
    }

    @PostMapping("/verify-challenge")
    @Operation(summary = "Verify signed challenge for step-up authentication")
    public ResponseEntity<StepUpVerifyResponse> verifyChallenge(
            @Valid @RequestBody StepUpVerifyRequest request) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Not authenticated"));
        return ResponseEntity.ok(stepUpAuthUseCase.verifyChallenge(currentUser.getId(), request));
    }
}
