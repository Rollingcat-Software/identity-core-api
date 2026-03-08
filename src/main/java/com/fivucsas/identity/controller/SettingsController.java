package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.UserSettings;
import com.fivucsas.identity.repository.UserSettingsRepository;
import com.fivucsas.identity.security.CustomUserDetails;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for user settings management.
 */
@RestController
@RequestMapping("/api/v1/users/me")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Settings", description = "User settings and preferences management")
public class SettingsController {

    private final UserSettingsRepository settingsRepository;

    @GetMapping("/settings")
    @Operation(summary = "Get current user settings")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserSettingsResponse> getSettings(
            @AuthenticationPrincipal CustomUserDetails user) {
        log.info("GET /api/v1/users/me/settings - User: {}", user.getUserId());

        UserSettings settings = settingsRepository.findById(user.getUserId())
                .orElseGet(() -> createDefaultSettings(user.getUserId()));

        return ResponseEntity.ok(toResponse(settings));
    }

    @PutMapping("/settings/security")
    @Operation(summary = "Update security settings")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> updateSecurity(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid SecuritySettingsRequest request) {
        log.info("PUT /api/v1/users/me/settings/security - User: {}", user.getUserId());

        UserSettings settings = getOrCreateSettings(user.getUserId());
        if (request.getTwoFactorEnabled() != null) {
            settings.setTwoFactorEnabled(request.getTwoFactorEnabled());
        }
        if (request.getSessionTimeout() != null) {
            settings.setSessionTimeout(request.getSessionTimeout());
        }
        settingsRepository.save(settings);

        return ResponseEntity.ok().build();
    }

    @PutMapping("/settings/notifications")
    @Operation(summary = "Update notification settings")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> updateNotifications(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid NotificationSettingsRequest request) {
        log.info("PUT /api/v1/users/me/settings/notifications - User: {}", user.getUserId());

        UserSettings settings = getOrCreateSettings(user.getUserId());
        settings.setEmailNotifications(request.isEmailNotifications());
        settings.setLoginAlerts(request.isLoginAlerts());
        settings.setSecurityAlerts(request.isSecurityAlerts());
        settings.setWeeklyReports(request.isWeeklyReports());
        settingsRepository.save(settings);

        return ResponseEntity.ok().build();
    }

    @PutMapping("/settings/appearance")
    @Operation(summary = "Update appearance settings")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> updateAppearance(
            @AuthenticationPrincipal CustomUserDetails user,
            @RequestBody @Valid AppearanceSettingsRequest request) {
        log.info("PUT /api/v1/users/me/settings/appearance - User: {}", user.getUserId());

        UserSettings settings = getOrCreateSettings(user.getUserId());
        settings.setDarkMode(request.isDarkMode());
        settings.setCompactView(request.isCompactView());
        if (request.getLanguage() != null) {
            settings.setLanguage(request.getLanguage());
        }
        settingsRepository.save(settings);

        return ResponseEntity.ok().build();
    }

    private UserSettings createDefaultSettings(java.util.UUID userId) {
        UserSettings settings = UserSettings.builder()
                .userId(userId)
                .build();
        return settingsRepository.save(settings);
    }

    private UserSettings getOrCreateSettings(java.util.UUID userId) {
        return settingsRepository.findById(userId)
                .orElseGet(() -> createDefaultSettings(userId));
    }

    private UserSettingsResponse toResponse(UserSettings settings) {
        UserSettingsResponse response = new UserSettingsResponse();
        response.setTwoFactorEnabled(settings.isTwoFactorEnabled());
        response.setSessionTimeout(settings.getSessionTimeout());
        response.setEmailNotifications(settings.isEmailNotifications());
        response.setLoginAlerts(settings.isLoginAlerts());
        response.setSecurityAlerts(settings.isSecurityAlerts());
        response.setWeeklyReports(settings.isWeeklyReports());
        response.setDarkMode(settings.isDarkMode());
        response.setCompactView(settings.isCompactView());
        response.setLanguage(settings.getLanguage());
        return response;
    }

    // DTOs
    @Data
    public static class UserSettingsResponse {
        private boolean twoFactorEnabled;
        private int sessionTimeout;
        private boolean emailNotifications;
        private boolean loginAlerts;
        private boolean securityAlerts;
        private boolean weeklyReports;
        private boolean darkMode;
        private boolean compactView;
        private String language;
    }

    @Data
    public static class SecuritySettingsRequest {
        private Boolean twoFactorEnabled;
        private Integer sessionTimeout;
    }

    @Data
    public static class NotificationSettingsRequest {
        private boolean emailNotifications;
        private boolean loginAlerts;
        private boolean securityAlerts;
        private boolean weeklyReports;
    }

    @Data
    public static class AppearanceSettingsRequest {
        private boolean darkMode;
        private boolean compactView;
        private String language;
    }
}
