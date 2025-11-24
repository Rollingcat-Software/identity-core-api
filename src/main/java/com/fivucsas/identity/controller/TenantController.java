package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CreateTenantCommand;
import com.fivucsas.identity.application.dto.command.UpdateTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantResponse;
import com.fivucsas.identity.application.port.input.ManageTenantUseCase;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller for tenant management.
 *
 * This controller handles tenant CRUD operations.
 * Access should be restricted to system administrators.
 */
@RestController
@RequestMapping("/api/v1/tenants")
@RequiredArgsConstructor
@Slf4j
public class TenantController {

    private final ManageTenantUseCase manageTenantUseCase;

    @PostMapping
    @PreAuthorize("hasAuthority('TENANT:CREATE')")
    public ResponseEntity<TenantResponse> createTenant(
            @Valid @RequestBody CreateTenantRequest request) {

        CreateTenantCommand command = CreateTenantCommand.builder()
            .name(request.getName())
            .slug(request.getSlug())
            .description(request.getDescription())
            .contactEmail(request.getContactEmail())
            .contactPhone(request.getContactPhone())
            .maxUsers(request.getMaxUsers())
            .biometricEnabled(request.getBiometricEnabled())
            .sessionTimeoutMinutes(request.getSessionTimeoutMinutes())
            .refreshTokenValidityDays(request.getRefreshTokenValidityDays())
            .mfaRequired(request.getMfaRequired())
            .build();

        TenantResponse response = manageTenantUseCase.createTenant(command);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{tenantId}")
    @PreAuthorize("hasAuthority('TENANT:READ')")
    public ResponseEntity<TenantResponse> getTenantById(@PathVariable String tenantId) {
        TenantResponse response = manageTenantUseCase.getTenantById(tenantId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/slug/{slug}")
    @PreAuthorize("hasAuthority('TENANT:READ')")
    public ResponseEntity<TenantResponse> getTenantBySlug(@PathVariable String slug) {
        TenantResponse response = manageTenantUseCase.getTenantBySlug(slug);
        return ResponseEntity.ok(response);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('TENANT:READ')")
    public ResponseEntity<List<TenantResponse>> getAllTenants() {
        List<TenantResponse> response = manageTenantUseCase.getAllTenants();
        return ResponseEntity.ok(response);
    }

    @PutMapping("/{tenantId}")
    @PreAuthorize("hasAuthority('TENANT:UPDATE')")
    public ResponseEntity<TenantResponse> updateTenant(
            @PathVariable String tenantId,
            @Valid @RequestBody UpdateTenantRequest request) {

        UpdateTenantCommand command = UpdateTenantCommand.builder()
            .tenantId(tenantId)
            .name(request.getName())
            .description(request.getDescription())
            .contactEmail(request.getContactEmail())
            .contactPhone(request.getContactPhone())
            .maxUsers(request.getMaxUsers())
            .biometricEnabled(request.getBiometricEnabled())
            .sessionTimeoutMinutes(request.getSessionTimeoutMinutes())
            .refreshTokenValidityDays(request.getRefreshTokenValidityDays())
            .mfaRequired(request.getMfaRequired())
            .build();

        TenantResponse response = manageTenantUseCase.updateTenant(command);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{tenantId}/activate")
    @PreAuthorize("hasAuthority('TENANT:MANAGE')")
    public ResponseEntity<TenantResponse> activateTenant(@PathVariable String tenantId) {
        TenantResponse response = manageTenantUseCase.activateTenant(tenantId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{tenantId}/suspend")
    @PreAuthorize("hasAuthority('TENANT:MANAGE')")
    public ResponseEntity<TenantResponse> suspendTenant(@PathVariable String tenantId) {
        TenantResponse response = manageTenantUseCase.suspendTenant(tenantId);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{tenantId}")
    @PreAuthorize("hasAuthority('TENANT:DELETE')")
    public ResponseEntity<Void> deleteTenant(@PathVariable String tenantId) {
        manageTenantUseCase.deleteTenant(tenantId);
        return ResponseEntity.noContent().build();
    }

    // ========== Request DTOs ==========

    @lombok.Data
    public static class CreateTenantRequest {
        private String name;
        private String slug;
        private String description;
        private String contactEmail;
        private String contactPhone;
        private Integer maxUsers;
        private Boolean biometricEnabled;
        private Integer sessionTimeoutMinutes;
        private Integer refreshTokenValidityDays;
        private Boolean mfaRequired;
    }

    @lombok.Data
    public static class UpdateTenantRequest {
        private String name;
        private String description;
        private String contactEmail;
        private String contactPhone;
        private Integer maxUsers;
        private Boolean biometricEnabled;
        private Integer sessionTimeoutMinutes;
        private Integer refreshTokenValidityDays;
        private Boolean mfaRequired;
    }
}
