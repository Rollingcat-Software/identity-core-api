package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.AuthMethodResponse;
import com.fivucsas.identity.application.dto.response.TenantAuthMethodResponse;
import com.fivucsas.identity.application.port.input.ManageAuthMethodUseCase;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST controller for auth method management.
 *
 * Merges: AuthMethodController + TenantAuthMethodController
 */
@RestController
@RequiredArgsConstructor
public class AuthMethodController {

    private final ManageAuthMethodUseCase manageAuthMethodUseCase;

    // --- /api/v1/auth-methods endpoints ---

    @GetMapping("/api/v1/auth-methods")
    public ResponseEntity<List<AuthMethodResponse>> getAllMethods() {
        return ResponseEntity.ok(manageAuthMethodUseCase.listAllMethods());
    }

    @GetMapping("/api/v1/auth-methods/{type}")
    public ResponseEntity<AuthMethodResponse> getMethodByType(@PathVariable AuthMethodType type) {
        return ResponseEntity.ok(manageAuthMethodUseCase.getMethodByType(type));
    }

    // --- /api/v1/tenants/{tenantId}/auth-methods endpoints (from TenantAuthMethodController) ---
    //
    // hasPermission(#tenantId, 'Tenant', ...) scopes by tenant: RbacPermissionEvaluator
    // refuses a 'Tenant' target outside the caller's tenant (canAccessTenant, ROOT stays
    // cross-tenant). The explicit @rbac.canAccessTenant(#tenantId) below repeats that
    // check on purpose, as defence in depth that does not depend on the evaluator.

    /**
     * Login-method catalog for one tenant's flow builder: the global catalog
     * plus PUZZLE when the PUZZLE layer is enabled for this tenant (canary).
     *
     * <p>{@code hasPermission(#tenantId, 'Tenant', ...)} already refuses another
     * tenant's id; the explicit {@code @rbac.canAccessTenant(#tenantId)} is kept as
     * defence in depth, because without a tenant check any tenant's admin could
     * probe whether another tenant is on the PUZZLE canary list.
     */
    @GetMapping("/api/v1/tenants/{tenantId}/auth-methods/catalog")
    @PreAuthorize("hasPermission(#tenantId, 'Tenant', 'auth_method:read') and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<List<AuthMethodResponse>> getTenantCatalog(@PathVariable UUID tenantId) {
        return ResponseEntity.ok(manageAuthMethodUseCase.listCatalogForTenant(tenantId));
    }

    @GetMapping("/api/v1/tenants/{tenantId}/auth-methods")
    @PreAuthorize("hasPermission(#tenantId, 'Tenant', 'auth_method:read') and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<List<TenantAuthMethodResponse>> getTenantMethods(@PathVariable UUID tenantId) {
        return ResponseEntity.ok(manageAuthMethodUseCase.listTenantMethods(tenantId));
    }

    @PutMapping("/api/v1/tenants/{tenantId}/auth-methods/{authMethodId}")
    @PreAuthorize("hasPermission(#tenantId, 'Tenant', 'auth_method:configure') and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<TenantAuthMethodResponse> configureMethod(
            @PathVariable UUID tenantId,
            @PathVariable UUID authMethodId,
            @RequestParam(defaultValue = "true") boolean enabled,
            // No-lock-out guard: disabling a method still required by an ACTIVE
            // auth flow is rejected (409) unless force=true. Default false so a
            // bare disable cannot silently break login.
            @RequestParam(defaultValue = "false") boolean force,
            @RequestBody(required = false) String configuration) {
        return ResponseEntity.ok(manageAuthMethodUseCase.configureTenantMethod(tenantId, authMethodId, enabled, configuration, force));
    }
}
