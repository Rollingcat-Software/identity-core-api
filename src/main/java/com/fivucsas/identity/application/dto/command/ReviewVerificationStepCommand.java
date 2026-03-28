package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotNull;

public record ReviewVerificationStepCommand(
    @NotNull Boolean approved,
    String notes
) {}
