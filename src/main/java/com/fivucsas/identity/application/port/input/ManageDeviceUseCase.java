package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;

import java.util.List;
import java.util.UUID;

public interface ManageDeviceUseCase {
    DeviceResponse registerDevice(UUID userId, UUID tenantId, RegisterDeviceCommand command);
    List<DeviceResponse> listUserDevices(UUID userId);
    List<DeviceResponse> listTenantDevices(UUID tenantId);
    /**
     * Platform-wide device listing for SUPER_ADMIN. Returns every device
     * across every tenant — caller scope MUST already have been verified.
     */
    List<DeviceResponse> listAllDevices();
    DeviceResponse updateDevice(UUID deviceId, String name, String pushToken);
    void removeDevice(UUID deviceId);
}
