package com.fivucsas.identity.application.dto.command;

import com.fivucsas.identity.domain.model.auth.OperationType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record StartAuthSessionCommand(
    @NotBlank String tenantSlug,
    @NotNull OperationType operationType,
    String platform,
    String deviceFingerprint,
    String email,
    String ipAddress,
    String userAgent
) {}
