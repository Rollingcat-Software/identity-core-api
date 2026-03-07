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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    @PreAuthorize("@rbac.isRoot()")
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
    @PreAuthorize("@rbac.hasPermission('tenant:read')")
    public ResponseEntity<TenantResponse> getTenantById(@PathVariable String tenantId) {
        TenantResponse response = manageTenantUseCase.getTenantById(tenantId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/slug/{slug}")
    @PreAuthorize("@rbac.hasPermission('tenant:read')")
    public ResponseEntity<TenantResponse> getTenantBySlug(@PathVariable String slug) {
        TenantResponse response = manageTenantUseCase.getTenantBySlug(slug);
        return ResponseEntity.ok(response);
    }

    @GetMapping
    @PreAuthorize("@rbac.hasPermission('tenant:read')")
    public ResponseEntity<Map<String, Object>> getAllTenants(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        List<TenantResponse> allTenants = manageTenantUseCase.getAllTenants();

        int totalElements = allTenants.size();
        int totalPages = (int) Math.ceil((double) totalElements / size);
        int fromIndex = Math.min(page * size, totalElements);
        int toIndex = Math.min(fromIndex + size, totalElements);

        List<TenantResponse> pagedTenants = allTenants.subList(fromIndex, toIndex);

        Map<String, Object> response = new HashMap<>();
        response.put("content", pagedTenants);
        response.put("totalElements", totalElements);
        response.put("totalPages", totalPages);
        response.put("page", page);
        response.put("size", size);

        return ResponseEntity.ok(response);
    }

    @PutMapping("/{tenantId}")
    @PreAuthorize("@rbac.hasPermission('tenant:configure')")
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
    @PreAuthorize("@rbac.isRoot()")
    public ResponseEntity<TenantResponse> activateTenant(@PathVariable String tenantId) {
        TenantResponse response = manageTenantUseCase.activateTenant(tenantId);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{tenantId}/suspend")
    @PreAuthorize("@rbac.isRoot()")
    public ResponseEntity<TenantResponse> suspendTenant(@PathVariable String tenantId) {
        TenantResponse response = manageTenantUseCase.suspendTenant(tenantId);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{tenantId}")
    @PreAuthorize("@rbac.isRoot()")
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
