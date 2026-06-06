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

    /**
     * #15 — Best-effort, idempotent UPSERT of a {@link com.fivucsas.identity.entity.UserDevice}
     * row on a SUCCESSFUL login completion, so a user who authenticated (web or
     * mobile) surfaces in the dashboard Devices view. Previously a UserDevice row
     * was only ever created on the approve-login push-token path, so plain
     * password/MFA logins left {@code user_devices} empty.
     *
     * <p>The fingerprint is DETERMINISTIC ({@code login:<userId>:<platform>}) so
     * repeated logins from the same platform UPDATE the same row rather than
     * accumulating duplicates. The device is bound to the user's OWN tenant;
     * platform + name are derived from the User-Agent when available.
     *
     * <p>This call MUST never fail the login — implementations swallow all
     * exceptions and return {@code null} on any error. Additive + reversible.
     *
     * @param userId    the just-authenticated user
     * @param userAgent the login request's User-Agent (may be null/blank)
     */
    void recordLoginDevice(UUID userId, String userAgent);

    void removeDevice(UUID deviceId);
}
