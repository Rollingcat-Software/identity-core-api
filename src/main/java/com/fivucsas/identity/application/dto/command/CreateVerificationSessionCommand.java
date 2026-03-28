package com.fivucsas.identity.application.dto.command;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record CreateVerificationSessionCommand(
    @NotNull UUID userId,
    @NotNull UUID tenantId,
    @NotNull UUID flowId
) {}
