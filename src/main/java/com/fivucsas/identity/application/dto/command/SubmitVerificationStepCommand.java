package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotNull;

public record SubmitVerificationStepCommand(
    @NotNull String stepType,
    Double confidence,
    String resultData,
    String errorMessage
) {}
