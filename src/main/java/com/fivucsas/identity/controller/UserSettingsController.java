package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.UserSettings;
import com.fivucsas.identity.repository.UserSettingsRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users/{userId}/settings")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Settings", description = "User settings management")
public class UserSettingsController {

    private final UserSettingsRepository userSettingsRepository;

    private static final Map<String, Object> DEFAULT_SETTINGS = Map.of(
            "notifications", Map.of(
                    "email", true,
                    "push", true,
                    "securityAlerts", true
            ),
            "security", Map.of(
                    "twoFactorEnabled", false,
                    "sessionTimeout", 30
            ),
            "appearance", Map.of(
                    "theme", "light",
                    "language", "en",
                    "density", "comfortable"
            )
    );

    @GetMapping
    @Operation(summary = "Get user settings")
    public ResponseEntity<Map<String, Object>> getUserSettings(@PathVariable String userId) {
        log.info("GET /api/v1/users/{}/settings", userId);

        UUID uuid = UUID.fromString(userId);
        return userSettingsRepository.findByUserId(uuid)
                .map(settings -> ResponseEntity.ok(settings.getSettings()))
                .orElseGet(() -> ResponseEntity.ok(new HashMap<>(DEFAULT_SETTINGS)));
    }

    @PutMapping
    @Operation(summary = "Update user settings")
    public ResponseEntity<Map<String, Object>> updateUserSettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> newSettings) {
        log.info("PUT /api/v1/users/{}/settings", userId);

        UUID uuid = UUID.fromString(userId);
        UserSettings settings = userSettingsRepository.findByUserId(uuid)
                .orElseGet(() -> UserSettings.builder()
                        .userId(uuid)
                        .settings(new HashMap<>(DEFAULT_SETTINGS))
                        .build());

        Map<String, Object> merged = new HashMap<>(settings.getSettings());
        merged.putAll(newSettings);
        settings.setSettings(merged);

        userSettingsRepository.save(settings);

        return ResponseEntity.ok(settings.getSettings());
    }

    @GetMapping("/notifications")
    @Operation(summary = "Get notification settings")
    public ResponseEntity<Object> getNotificationSettings(@PathVariable String userId) {
        return getSettingsSection(userId, "notifications");
    }

    @PutMapping("/notifications")
    @Operation(summary = "Update notification settings")
    public ResponseEntity<Object> updateNotificationSettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> notificationSettings) {
        return updateSettingsSection(userId, "notifications", notificationSettings);
    }

    @GetMapping("/security")
    @Operation(summary = "Get security settings")
    public ResponseEntity<Object> getSecuritySettings(@PathVariable String userId) {
        return getSettingsSection(userId, "security");
    }

    @PutMapping("/security")
    @Operation(summary = "Update security settings")
    public ResponseEntity<Object> updateSecuritySettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> securitySettings) {
        return updateSettingsSection(userId, "security", securitySettings);
    }

    @GetMapping("/appearance")
    @Operation(summary = "Get appearance settings")
    public ResponseEntity<Object> getAppearanceSettings(@PathVariable String userId) {
        return getSettingsSection(userId, "appearance");
    }

    @PutMapping("/appearance")
    @Operation(summary = "Update appearance settings")
    public ResponseEntity<Object> updateAppearanceSettings(
            @PathVariable String userId,
            @RequestBody Map<String, Object> appearanceSettings) {
        return updateSettingsSection(userId, "appearance", appearanceSettings);
    }

    private ResponseEntity<Object> getSettingsSection(String userId, String section) {
        UUID uuid = UUID.fromString(userId);
        Map<String, Object> allSettings = userSettingsRepository.findByUserId(uuid)
                .map(UserSettings::getSettings)
                .orElse(DEFAULT_SETTINGS);

        Object sectionSettings = allSettings.getOrDefault(section, DEFAULT_SETTINGS.get(section));
        return ResponseEntity.ok(sectionSettings);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> updateSettingsSection(String userId, String section, Map<String, Object> sectionSettings) {
        UUID uuid = UUID.fromString(userId);
        UserSettings settings = userSettingsRepository.findByUserId(uuid)
                .orElseGet(() -> UserSettings.builder()
                        .userId(uuid)
                        .settings(new HashMap<>(DEFAULT_SETTINGS))
                        .build());

        Map<String, Object> allSettings = new HashMap<>(settings.getSettings());
        allSettings.put(section, sectionSettings);
        settings.setSettings(allSettings);
        userSettingsRepository.save(settings);

        return ResponseEntity.ok(sectionSettings);
    }
}
