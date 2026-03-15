package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserDevice;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.application.port.output.UserDeviceRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
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
    private final TenantRepository tenantRepository;

    @Override
    @Transactional
    public DeviceResponse registerDevice(UUID userId, UUID tenantId, RegisterDeviceCommand command) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant not found: " + tenantId));

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
