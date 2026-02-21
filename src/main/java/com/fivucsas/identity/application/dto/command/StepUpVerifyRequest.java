package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotBlank;

public record StepUpVerifyRequest(
    @NotBlank String deviceFingerprint,
    @NotBlank String challenge,
    @NotBlank String signature
) {}
