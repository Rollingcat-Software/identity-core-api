package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.domain.exception.DeviceLimitExceededException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserDevice;
import com.fivucsas.identity.repository.JpaTenantRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ManageDeviceService implements ManageDeviceUseCase {

    private final UserDeviceRepositoryPort userDeviceRepository;
    private final UserRepository userRepository;
    private final JpaTenantRepository tenantRepository;

    /**
     * Hard cap on per-user active devices. INVESTIGATION_MASTER_2026-05-07
     * §"user constraints": closes the unbounded WebAuthn allowList growth.
     * Defaults to 10 — overridden by {@code APP_SECURITY_MAX_DEVICES_PER_USER}.
     */
    @Value("${app.security.max-devices-per-user:10}")
    private int maxDevicesPerUser;

    @Override
    @Transactional
    public DeviceResponse registerDevice(UUID userId, UUID tenantId, RegisterDeviceCommand command) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

        // INVESTIGATION_MASTER_2026-05-07 §"user constraints":
        // enforce the per-user device cap BEFORE creating a new row, but
        // permit re-registration of an existing device fingerprint (which
        // is an UPDATE, not a CREATE) to bypass the cap.
        boolean isExistingFingerprint = userDeviceRepository
                .findByUserIdAndDeviceFingerprint(userId, command.deviceFingerprint())
                .isPresent();
        if (!isExistingFingerprint) {
            int currentDevices = userDeviceRepository.findAllByUserId(userId).size();
            if (currentDevices >= maxDevicesPerUser) {
                throw new DeviceLimitExceededException(currentDevices, maxDevicesPerUser);
            }
        }

        UserDevice device = userDeviceRepository
                .findByUserIdAndDeviceFingerprint(userId, command.deviceFingerprint())
                .orElseGet(() -> UserDevice.builder()
                        .user(user)
                        .tenant(tenant)
                        .deviceFingerprint(command.deviceFingerprint())
                        .platform(command.platform())
                        .capabilities(command.capabilities() != null ? command.capabilities() : List.of())
                        .build());

        device.updateName(command.deviceName());
        if (command.pushToken() != null) {
            device.updatePushToken(command.pushToken());
        }
        device.updateLastUsed();

        return DeviceResponse.from(userDeviceRepository.save(device));
    }

    @Override
    public List<DeviceResponse> listUserDevices(UUID userId) {
        return userDeviceRepository.findAllByUserId(userId).stream()
                .map(DeviceResponse::from)
                .toList();
    }

    @Override
    public List<DeviceResponse> listTenantDevices(UUID tenantId) {
        return userDeviceRepository.findAllByTenantId(tenantId).stream()
                .map(DeviceResponse::from)
                .toList();
    }

    /**
     * Hard server-side cap on platform-wide device dumps. Copilot post-merge
     * round 5 flagged the unbounded `findAll()`: above this limit the SUPER_ADMIN
     * UI MUST switch to a paged endpoint (planned follow-up — see
     * {@code listTenantDevices(tenantId)} for the existing tenant-scoped path).
     * The limit is intentionally generous so existing dashboards keep working
     * while the platform is small, but bounded so a runaway request can't
     * pull a million rows.
     */
    private static final int MAX_PLATFORM_WIDE_DEVICES = 1000;

    @Override
    public List<DeviceResponse> listAllDevices() {
        return userDeviceRepository.findAll().stream()
                .limit(MAX_PLATFORM_WIDE_DEVICES)
                .map(DeviceResponse::from)
                .toList();
    }

    @Override
    @Transactional
    public DeviceResponse updateDevice(UUID deviceId, String name, String pushToken) {
        UserDevice device = userDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new EntityNotFoundException("Device not found: " + deviceId));
        if (name != null) device.updateName(name);
        if (pushToken != null) device.updatePushToken(pushToken);
        return DeviceResponse.from(userDeviceRepository.save(device));
    }

    @Override
    @Transactional
    public void removeDevice(UUID deviceId) {
        UserDevice device = userDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new EntityNotFoundException("Device not found: " + deviceId));
        userDeviceRepository.delete(device);
    }
}
