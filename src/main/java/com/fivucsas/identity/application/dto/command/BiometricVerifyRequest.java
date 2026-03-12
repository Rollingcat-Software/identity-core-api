package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotBlank;

/**
 * Client request DTO for biometric challenge verification.
 * Maps client field names to internal StepUpVerifyRequest.
 */
public record BiometricVerifyRequest(
    @NotBlank String challengeId,
    @NotBlank String keyId,
    @NotBlank String signatureBase64
) {}
