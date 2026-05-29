package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CreateTenantCommand;
import com.fivucsas.identity.application.dto.command.UpdateTenantCommand;
import com.fivucsas.identity.application.dto.response.TenantResponse;
import com.fivucsas.identity.application.port.input.ManageTenantUseCase;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
    private final RbacAuthorizationService rbacService;
    private final TenantScopeResolver tenantScopeResolver;

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
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<TenantResponse> getTenantById(@PathVariable String tenantId) {
        // Non-SUPER_ADMIN callers may only fetch their own tenant. 404 rather
        // than 403 to avoid leaking which tenant IDs exist.
        UUID target;
        try {
            target = UUID.fromString(tenantId);
        } catch (IllegalArgumentException e) {
            throw new com.fivucsas.identity.exception.ResourceNotFoundException("Tenant not found: " + tenantId);
        }
        if (!tenantScopeResolver.canAccessTenant(target)) {
            throw new com.fivucsas.identity.exception.ResourceNotFoundException("Tenant not found: " + tenantId);
        }
        TenantResponse response = manageTenantUseCase.getTenantById(tenantId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/slug/{slug}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<TenantResponse> getTenantBySlug(@PathVariable String slug) {
        TenantResponse response = manageTenantUseCase.getTenantBySlug(slug);
        // Tenant-scope check — non-SUPER_ADMIN may only resolve their own.
        try {
            UUID target = UUID.fromString(response.getId());
            if (!tenantScopeResolver.canAccessTenant(target)) {
                throw new com.fivucsas.identity.exception.ResourceNotFoundException("Tenant not found: " + slug);
            }
        } catch (IllegalArgumentException e) {
            throw new com.fivucsas.identity.exception.ResourceNotFoundException("Tenant not found: " + slug);
        }
        return ResponseEntity.ok(response);
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> getAllTenants(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        // Listing ALL tenants system-wide is a SUPER_ADMIN operation. For
        // non-SUPER_ADMIN callers we return only the caller's own tenant so
        // the dashboard renders a usable list (rather than 403'ing and
        // breaking the page). This never leaks other tenants' data.
        List<TenantResponse> visible;
        if (tenantScopeResolver.isUnrestricted()) {
            visible = manageTenantUseCase.getAllTenants();
        } else {
            UUID scope = tenantScopeResolver.currentScope();
            if (scope == null || scope.equals(TenantScopeResolver.FAIL_CLOSED_EMPTY_SCOPE)) {
                visible = List.of();
            } else {
                try {
                    visible = List.of(manageTenantUseCase.getTenantById(scope.toString()));
                } catch (Exception e) {
                    visible = List.of();
                }
            }
        }

        int totalElements = visible.size();
        int totalPages = size == 0 ? 0 : (int) Math.ceil((double) totalElements / size);
        int fromIndex = Math.min(page * size, totalElements);
        int toIndex = Math.min(fromIndex + size, totalElements);

        List<TenantResponse> pagedTenants = visible.subList(fromIndex, toIndex);

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
            .enforceDomainMatching(request.getEnforceDomainMatching())
            .defaultMemberRole(request.getDefaultMemberRole())
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
        @NotBlank(message = "Tenant name is required")
        @Size(min = 2, max = 100, message = "Tenant name must be between 2 and 100 characters")
        private String name;

        @NotBlank(message = "Tenant slug is required")
        @Size(min = 2, max = 50, message = "Tenant slug must be between 2 and 50 characters")
        private String slug;

        @Size(max = 500, message = "Description must not exceed 500 characters")
        private String description;

        @Email(message = "Contact email must be valid")
        private String contactEmail;

        private String contactPhone;

        @Min(value = 1, message = "Max users must be at least 1")
        private Integer maxUsers;

        private Boolean biometricEnabled;

        @Min(value = 1, message = "Session timeout must be at least 1 minute")
        private Integer sessionTimeoutMinutes;

        @Min(value = 1, message = "Refresh token validity must be at least 1 day")
        private Integer refreshTokenValidityDays;

        private Boolean mfaRequired;
    }

    @lombok.Data
    public static class UpdateTenantRequest {
        @Size(min = 2, max = 100, message = "Tenant name must be between 2 and 100 characters")
        private String name;

        @Size(max = 500, message = "Description must not exceed 500 characters")
        private String description;

        @Email(message = "Contact email must be valid")
        private String contactEmail;

        private String contactPhone;

        @Min(value = 1, message = "Max users must be at least 1")
        private Integer maxUsers;

        private Boolean biometricEnabled;

        @Min(value = 1, message = "Session timeout must be at least 1 minute")
        private Integer sessionTimeoutMinutes;

        @Min(value = 1, message = "Refresh token validity must be at least 1 day")
        private Integer refreshTokenValidityDays;

        private Boolean mfaRequired;

        /**
         * Opt-in email-domain enforcement (V62). When true, only registrants
         * whose email domain is in this tenant's tenant_email_domains may join.
         */
        private Boolean enforceDomainMatching;

        /**
         * Per-tenant default member role (V64) auto-assigned to users who join
         * via a verified email domain. {@code null} = leave unchanged; blank =
         * clear (fall back to the seeded baseline role).
         */
        @Size(max = 100, message = "Default member role must not exceed 100 characters")
        private String defaultMemberRole;
    }
}
