package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.domain.exception.DeviceLimitExceededException;
import com.fivucsas.identity.domain.model.auth.DevicePlatform;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserDevice;
import com.fivucsas.identity.repository.JpaTenantRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
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
     * round 5 flagged the unbounded `findAll()`: above this limit the ROOT
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
    public DeviceResponse updatePushToken(UUID userId, String token, String platform) {
        List<UserDevice> devices = userDeviceRepository.findAllByUserId(userId);
        if (devices.isEmpty()) {
            // #15 — UPSERT instead of throwing. A mobile-logged-in user has no
            // UserDevice row (login/token paths don't create one), so the
            // approve-login push-token registration used to 404 silently and the
            // user never appeared in the dashboard Devices view. Create a device
            // on first push-token call. The fingerprint is DETERMINISTIC
            // (push:<userId>:<platform>) so repeated calls update the same row
            // rather than accumulating duplicates. Correctly tenant-scoped to the
            // user's own tenant. Additive + reversible.
            return upsertPushTokenDevice(userId, token, platform);
        }

        // Prefer a device matching the requested platform; otherwise fall back
        // to any of the user's devices. Among candidates, pick the
        // most-recently-used so the token lands on the device the user is
        // actively driving the approve-login from.
        DevicePlatform requested = parsePlatform(platform);
        UserDevice target = devices.stream()
                .filter(d -> requested == null || requested.equals(d.getPlatform()))
                .max(Comparator.comparing(
                        UserDevice::getLastUsedAt,
                        Comparator.nullsFirst(Comparator.naturalOrder())))
                .orElseGet(() -> devices.stream()
                        .max(Comparator.comparing(
                                UserDevice::getLastUsedAt,
                                Comparator.nullsFirst(Comparator.naturalOrder())))
                        .orElseThrow(() -> new EntityNotFoundException(
                                "No device registered for user: " + userId)));

        target.updatePushToken(token);
        return DeviceResponse.from(userDeviceRepository.save(target));
    }

    /**
     * #15 — Creates (or refreshes, if it already exists) a UserDevice for a user
     * who has none yet, so a mobile-logged-in user surfaces in the dashboard
     * Devices view. The device is bound to the user's OWN tenant and uses a
     * deterministic fingerprint so the operation is idempotent across repeated
     * push-token registrations from the same platform.
     */
    private DeviceResponse upsertPushTokenDevice(UUID userId, String token, String platform) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
        Tenant tenant = user.getTenant();
        if (tenant == null) {
            // A user row should always carry a tenant; if not, there is nowhere
            // safe to scope the device, so preserve the prior fail behavior.
            throw new EntityNotFoundException("No tenant for user: " + userId);
        }
        DevicePlatform resolvedPlatform = parsePlatform(platform);
        if (resolvedPlatform == null) {
            resolvedPlatform = DevicePlatform.ANDROID; // push tokens come from mobile
        }
        // Deterministic fingerprint → idempotent upsert (no duplicate rows).
        String fingerprint = "push:" + userId + ":" + resolvedPlatform.name();

        final DevicePlatform platformForBuild = resolvedPlatform;
        UserDevice device = userDeviceRepository
                .findByUserIdAndDeviceFingerprint(userId, fingerprint)
                .orElseGet(() -> UserDevice.builder()
                        .user(user)
                        .tenant(tenant)
                        .deviceName(platformForBuild.name() + " device")
                        .deviceFingerprint(fingerprint)
                        .platform(platformForBuild)
                        .capabilities(List.of())
                        .build());

        device.updatePushToken(token);
        device.updateLastUsed();
        return DeviceResponse.from(userDeviceRepository.save(device));
    }

    /**
     * #15 — Best-effort, idempotent login-device upsert. See
     * {@link ManageDeviceUseCase#recordLoginDevice(UUID, String)}. NEVER throws:
     * any failure is logged and swallowed so a device-tracking hiccup can't break
     * the login it is observing.
     */
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordLoginDevice(UUID userId, String userAgent) {
        try {
            User user = userRepository.findById(userId).orElse(null);
            if (user == null) {
                return;
            }
            Tenant tenant = user.getTenant();
            if (tenant == null) {
                // No tenant → nowhere safe to scope the device. Skip (don't fail login).
                return;
            }

            DevicePlatform platform = platformFromUserAgent(userAgent);
            // Deterministic fingerprint → idempotent upsert (no duplicate rows on
            // repeated logins from the same platform).
            String fingerprint = "login:" + userId + ":" + platform.name();
            String deviceName = deviceNameFor(userAgent, platform);

            final DevicePlatform platformForBuild = platform;
            UserDevice device = userDeviceRepository
                    .findByUserIdAndDeviceFingerprint(userId, fingerprint)
                    .orElseGet(() -> UserDevice.builder()
                            .user(user)
                            .tenant(tenant)
                            .deviceName(deviceName)
                            .deviceFingerprint(fingerprint)
                            .platform(platformForBuild)
                            .capabilities(List.of())
                            .build());

            // Refresh the name on each login (UA may change) and stamp last-used.
            device.updateName(deviceName);
            device.updateLastUsed();
            userDeviceRepository.save(device);
        } catch (RuntimeException e) {
            // Best-effort: a device-tracking failure must NEVER fail the login.
            log.warn("recordLoginDevice failed for user {} (login continues): {}",
                    userId, e.getMessage());
        }
    }

    /**
     * Maps a browser/app User-Agent to a {@link DevicePlatform}. Mobile UAs win
     * over the desktop-OS substring (Android/iOS UAs also contain "Linux"/"Mac OS"),
     * so the order matters. Unknown/blank → WEB (the dashboard surface is the only
     * caller that has no explicit platform).
     */
    private static DevicePlatform platformFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return DevicePlatform.WEB;
        }
        String ua = userAgent.toLowerCase(java.util.Locale.ROOT);
        if (ua.contains("android")) {
            return DevicePlatform.ANDROID;
        }
        if (ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios")) {
            return DevicePlatform.IOS;
        }
        // A native desktop client identifies itself explicitly; everything else
        // (Chrome/Firefox/Safari/Edge on Win/Mac/Linux) is the WEB surface.
        if (ua.contains("electron") || ua.contains("desktop-app")) {
            return DevicePlatform.DESKTOP;
        }
        return DevicePlatform.WEB;
    }

    /**
     * Human-readable device name. Reuses the existing User-Agent parser used for
     * the sessions list ("Chrome on Windows"); falls back to the platform name
     * when the UA is absent.
     */
    private static String deviceNameFor(String userAgent, DevicePlatform platform) {
        if (userAgent != null && !userAgent.isBlank()) {
            return com.fivucsas.identity.application.dto.response.SessionResponse
                    .extractDeviceInfo(userAgent);
        }
        return platform.name() + " device";
    }

    private static DevicePlatform parsePlatform(String platform) {
        if (platform == null || platform.isBlank()) {
            return null;
        }
        try {
            return DevicePlatform.valueOf(platform.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @Override
    @Transactional
    public void removeDevice(UUID deviceId) {
        UserDevice device = userDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new EntityNotFoundException("Device not found: " + deviceId));
        userDeviceRepository.delete(device);
    }
}
