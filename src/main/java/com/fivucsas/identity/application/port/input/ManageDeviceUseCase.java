package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;

import java.util.List;
import java.util.UUID;

public interface ManageDeviceUseCase {
    DeviceResponse registerDevice(UUID userId, UUID tenantId, RegisterDeviceCommand command);
    List<DeviceResponse> listUserDevices(UUID userId);
    List<DeviceResponse> listTenantDevices(UUID tenantId);
    DeviceResponse updateDevice(UUID deviceId, String name, String pushToken);
    void removeDevice(UUID deviceId);
}
