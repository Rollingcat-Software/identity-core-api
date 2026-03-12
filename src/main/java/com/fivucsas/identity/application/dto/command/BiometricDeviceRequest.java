package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotBlank;

/**
 * Client request DTO for biometric device registration.
 * Maps client field names to internal StepUpDeviceRequest.
 */
public record BiometricDeviceRequest(
    @NotBlank String keyId,
    @NotBlank String platform,
    @NotBlank String publicKeyJwk
) {}
