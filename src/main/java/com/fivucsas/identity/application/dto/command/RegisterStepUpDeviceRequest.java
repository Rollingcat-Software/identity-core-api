package com.fivucsas.identity.application.dto.command;

import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record RegisterStepUpDeviceRequest(
    @NotBlank String deviceFingerprint,
    @NotNull DevicePlatform platform,
    @NotBlank String publicKey,
    String publicKeyAlgorithm,
    String deviceName,
    List<String> capabilities
) {}
