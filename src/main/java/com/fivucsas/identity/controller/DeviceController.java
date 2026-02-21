package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.RegisterDeviceCommand;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/devices")
@RequiredArgsConstructor
public class DeviceController {

    private final ManageDeviceUseCase manageDeviceUseCase;

    @GetMapping
    @PreAuthorize("hasPermission(null, 'Device', 'device:read')")
    public ResponseEntity<List<DeviceResponse>> getDevices(
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) UUID tenantId) {
        if (userId != null) {
            return ResponseEntity.ok(manageDeviceUseCase.listUserDevices(userId));
        }
        if (tenantId != null) {
            return ResponseEntity.ok(manageDeviceUseCase.listTenantDevices(tenantId));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping
    @PreAuthorize("hasPermission(null, 'Device', 'device:register')")
    public ResponseEntity<DeviceResponse> registerDevice(
            @RequestParam UUID userId,
            @RequestParam UUID tenantId,
            @RequestBody RegisterDeviceCommand command) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(manageDeviceUseCase.registerDevice(userId, tenantId, command));
    }

    @DeleteMapping("/{deviceId}")
    @PreAuthorize("hasPermission(null, 'Device', 'device:delete')")
    public ResponseEntity<Void> removeDevice(@PathVariable UUID deviceId) {
        manageDeviceUseCase.removeDevice(deviceId);
        return ResponseEntity.noContent().build();
    }
}
