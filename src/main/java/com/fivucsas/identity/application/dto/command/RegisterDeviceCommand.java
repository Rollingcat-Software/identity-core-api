package com.fivucsas.identity.application.dto.command;

import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record RegisterDeviceCommand(
    String deviceName,
    @NotNull DevicePlatform platform,
    @NotBlank String deviceFingerprint,
    List<String> capabilities,
    String pushToken
) {}
