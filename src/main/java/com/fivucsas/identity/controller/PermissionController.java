package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.query.GetPermissionByIdQuery;
import com.fivucsas.identity.application.dto.response.PermissionResponse;
import com.fivucsas.identity.application.port.input.ManagePermissionUseCase;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller for permission management endpoints.
 *
 * Permissions are read-only (created via database migrations).
 * All endpoints require role:read permission.
 */
@RestController
@RequestMapping("/api/v1/permissions")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Permission Management", description = "Permission read operations")
public class PermissionController {

    private final ManagePermissionUseCase managePermissionUseCase;

    @GetMapping
    @Operation(summary = "Get all permissions")
    @PreAuthorize("@rbac.hasPermission('permission:read')")
    public ResponseEntity<List<PermissionResponse>> getAllPermissions() {
        log.info("GET /api/v1/permissions - Get all permissions");

        List<PermissionResponse> permissions = managePermissionUseCase.getAllPermissions();

        return ResponseEntity.ok(permissions);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get permission by ID")
    @PreAuthorize("@rbac.hasPermission('permission:read')")
    public ResponseEntity<PermissionResponse> getPermissionById(@PathVariable String id) {
        log.info("GET /api/v1/permissions/{} - Get permission by ID", id);

        GetPermissionByIdQuery query = GetPermissionByIdQuery.builder()
                .permissionId(id)
                .build();

        PermissionResponse permission = managePermissionUseCase.getPermissionById(query);

        return ResponseEntity.ok(permission);
    }

    @GetMapping("/resource/{resource}")
    @Operation(summary = "Get permissions by resource")
    @PreAuthorize("@rbac.hasPermission('permission:read')")
    public ResponseEntity<List<PermissionResponse>> getPermissionsByResource(@PathVariable String resource) {
        log.info("GET /api/v1/permissions/resource/{} - Get permissions by resource", resource);

        List<PermissionResponse> permissions = managePermissionUseCase.getPermissionsByResource(resource);

        return ResponseEntity.ok(permissions);
    }
}
