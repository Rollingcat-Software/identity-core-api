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

    @GetMapping("/api/v1/tenants/{tenantId}/auth-methods")
    @PreAuthorize("hasPermission(#tenantId, 'Tenant', 'auth_method:read')")
    public ResponseEntity<List<TenantAuthMethodResponse>> getTenantMethods(@PathVariable UUID tenantId) {
        return ResponseEntity.ok(manageAuthMethodUseCase.listTenantMethods(tenantId));
    }

    @PutMapping("/api/v1/tenants/{tenantId}/auth-methods/{authMethodId}")
    @PreAuthorize("hasPermission(#tenantId, 'Tenant', 'auth_method:configure')")
    public ResponseEntity<TenantAuthMethodResponse> configureMethod(
            @PathVariable UUID tenantId,
            @PathVariable UUID authMethodId,
            @RequestParam(defaultValue = "true") boolean enabled,
            @RequestBody(required = false) String configuration) {
        return ResponseEntity.ok(manageAuthMethodUseCase.configureTenantMethod(tenantId, authMethodId, enabled, configuration));
    }
}
