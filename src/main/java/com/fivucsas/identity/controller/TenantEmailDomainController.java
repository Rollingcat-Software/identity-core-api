package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.TenantEmailDomainResponse;
import com.fivucsas.identity.application.port.input.ManageTenantEmailDomainUseCase;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Admin CRUD for a tenant's email-domain registry
 * ({@code tenant_email_domains}, V44).
 *
 * <p>Gating: {@code @rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)}.
 * {@code isTenantAdmin()} is {@code userType >= TENANT_ADMIN} (true for ROOT)
 * and {@code canAccessTenant()} returns true for ROOT and for a tenant-admin's
 * own tenant — so SUPER_ADMIN/ROOT retain cross-tenant access while a
 * TENANT_ADMIN is confined to their own tenant. This mirrors how
 * {@code TenantController} gates its configure/update paths.</p>
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/email-domains")
@RequiredArgsConstructor
@Slf4j
public class TenantEmailDomainController {

    private final ManageTenantEmailDomainUseCase manageEmailDomains;

    @GetMapping
    @PreAuthorize("@rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<List<TenantEmailDomainResponse>> listDomains(
            @PathVariable UUID tenantId) {
        return ResponseEntity.ok(manageEmailDomains.listDomains(tenantId));
    }

    @PostMapping
    @PreAuthorize("@rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<TenantEmailDomainResponse> addDomain(
            @PathVariable UUID tenantId,
            @Valid @RequestBody AddEmailDomainRequest request) {
        TenantEmailDomainResponse response = manageEmailDomains.addDomain(
                tenantId,
                request.getDomain(),
                Boolean.TRUE.equals(request.getIsPrimary()));
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @DeleteMapping("/{domain}")
    @PreAuthorize("@rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<Void> removeDomain(
            @PathVariable UUID tenantId,
            @PathVariable String domain) {
        manageEmailDomains.removeDomain(tenantId, domain);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{domain}/primary")
    @PreAuthorize("@rbac.isTenantAdmin() and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<TenantEmailDomainResponse> setPrimary(
            @PathVariable UUID tenantId,
            @PathVariable String domain) {
        return ResponseEntity.ok(manageEmailDomains.setPrimaryDomain(tenantId, domain));
    }

    // ========== Request DTOs ==========

    @lombok.Data
    public static class AddEmailDomainRequest {
        @NotBlank(message = "Email domain is required")
        @Size(max = 253, message = "Email domain must not exceed 253 characters")
        private String domain;

        /** When true, set this as the tenant's single primary domain. */
        private Boolean isPrimary;
    }
}
