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
     * Platform-wide device listing for ROOT. Returns every device
     * across every tenant — caller scope MUST already have been verified.
     */
    List<DeviceResponse> listAllDevices();
    DeviceResponse updateDevice(UUID deviceId, String name, String pushToken);

    /**
     * Stores/refreshes the push-notification token for a user's device on the
     * given platform (used by the number-matching approve-login push channel).
     * Resolves the user's device for {@code platform}; when several exist the
     * most-recently-used one is updated. Returns the updated device.
     *
     * @param platform optional platform hint (WEB/ANDROID/IOS/DESKTOP); when
     *                 null the user's most-recently-used device is updated.
     */
    DeviceResponse updatePushToken(UUID userId, String token, String platform);

    void removeDevice(UUID deviceId);
}
