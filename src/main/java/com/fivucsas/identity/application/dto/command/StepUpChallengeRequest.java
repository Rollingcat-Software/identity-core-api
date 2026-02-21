package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotBlank;

public record StepUpChallengeRequest(
    @NotBlank String deviceFingerprint
) {}
