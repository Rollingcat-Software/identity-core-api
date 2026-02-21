package com.fivucsas.identity.application.dto.response;

import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import com.fivucsas.identity.entity.UserDevice;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record DeviceResponse(
    UUID id,
    String deviceName,
    DevicePlatform platform,
    String deviceFingerprint,
    List<String> capabilities,
    boolean isTrusted,
    Instant lastUsedAt,
    Instant registeredAt
) {
    public static DeviceResponse from(UserDevice entity) {
        return new DeviceResponse(
            entity.getId(),
            entity.getDeviceName(),
            entity.getPlatform(),
            entity.getDeviceFingerprint(),
            entity.getCapabilities(),
            entity.isTrusted(),
            entity.getLastUsedAt(),
            entity.getRegisteredAt()
        );
    }
}
