package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.TenantAuthMethodResponse;
import com.fivucsas.identity.application.port.input.ManageAuthMethodUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/auth-methods")
@RequiredArgsConstructor
public class TenantAuthMethodController {

    private final ManageAuthMethodUseCase manageAuthMethodUseCase;

    @GetMapping
    @PreAuthorize("hasPermission(#tenantId, 'Tenant', 'auth_method:read')")
    public ResponseEntity<List<TenantAuthMethodResponse>> getTenantMethods(@PathVariable UUID tenantId) {
        return ResponseEntity.ok(manageAuthMethodUseCase.listTenantMethods(tenantId));
    }

    @PutMapping("/{authMethodId}")
    @PreAuthorize("hasPermission(#tenantId, 'Tenant', 'auth_method:configure')")
    public ResponseEntity<TenantAuthMethodResponse> configureMethod(
            @PathVariable UUID tenantId,
            @PathVariable UUID authMethodId,
            @RequestParam(defaultValue = "true") boolean enabled,
            @RequestBody(required = false) String configuration) {
        return ResponseEntity.ok(manageAuthMethodUseCase.configureTenantMethod(tenantId, authMethodId, enabled, configuration));
    }
}
