package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotNull;

import java.util.Map;

public record CompleteAuthStepCommand(
    @NotNull Map<String, Object> data
) {}
