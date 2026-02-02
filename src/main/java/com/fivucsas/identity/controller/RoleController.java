package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.*;
import com.fivucsas.identity.application.dto.query.*;
import com.fivucsas.identity.application.dto.response.RoleResponse;
import com.fivucsas.identity.application.port.input.ManageRoleUseCase;
import com.fivucsas.identity.dto.CreateRoleRequest;
import com.fivucsas.identity.dto.UpdateRoleRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST controller for role management endpoints.
 *
 * All endpoints require appropriate RBAC permissions.
 */
@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Role Management", description = "Role CRUD and permission assignment operations")
public class RoleController {

    private final ManageRoleUseCase manageRoleUseCase;

    @GetMapping
    @Operation(summary = "Get all roles")
    @PreAuthorize("@rbac.hasPermission('role:read')")
    public ResponseEntity<List<RoleResponse>> getAllRoles(
            @RequestParam(required = false, defaultValue = "false") boolean includeInactive) {
        log.info("GET /api/v1/roles - Get all roles, includeInactive={}", includeInactive);

        GetAllRolesQuery query = GetAllRolesQuery.builder()
                .includeInactive(includeInactive)
                .build();

        List<RoleResponse> roles = manageRoleUseCase.getAllRoles(query);

        return ResponseEntity.ok(roles);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get role by ID")
    @PreAuthorize("@rbac.hasPermission('role:read')")
    public ResponseEntity<RoleResponse> getRoleById(@PathVariable String id) {
        log.info("GET /api/v1/roles/{} - Get role by ID", id);

        GetRoleByIdQuery query = GetRoleByIdQuery.builder()
                .roleId(id)
                .build();

        RoleResponse role = manageRoleUseCase.getRoleById(query);

        return ResponseEntity.ok(role);
    }

    @GetMapping("/tenant/{tenantId}")
    @Operation(summary = "Get roles by tenant")
    @PreAuthorize("@rbac.hasPermission('role:read')")
    public ResponseEntity<List<RoleResponse>> getRolesByTenant(@PathVariable String tenantId) {
        log.info("GET /api/v1/roles/tenant/{} - Get roles by tenant", tenantId);

        GetRolesByTenantQuery query = GetRolesByTenantQuery.builder()
                .tenantId(tenantId)
                .build();

        List<RoleResponse> roles = manageRoleUseCase.getRolesByTenant(query);

        return ResponseEntity.ok(roles);
    }

    @PostMapping
    @Operation(summary = "Create new role")
    @PreAuthorize("@rbac.hasPermission('role:create')")
    public ResponseEntity<RoleResponse> createRole(@Valid @RequestBody CreateRoleRequest request) {
        log.info("POST /api/v1/roles - Create role: {}", request.getName());

        CreateRoleCommand command = CreateRoleCommand.builder()
                .name(request.getName())
                .description(request.getDescription())
                .tenantId(request.getTenantId())
                .permissionIds(request.getPermissionIds())
                .systemRole(false) // Only system can create system roles
                .build();

        RoleResponse role = manageRoleUseCase.createRole(command);

        return ResponseEntity.status(HttpStatus.CREATED).body(role);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update role")
    @PreAuthorize("@rbac.hasPermission('role:update')")
    public ResponseEntity<RoleResponse> updateRole(
            @PathVariable String id,
            @Valid @RequestBody UpdateRoleRequest request) {
        log.info("PUT /api/v1/roles/{} - Update role", id);

        UpdateRoleCommand command = UpdateRoleCommand.builder()
                .roleId(id)
                .name(request.getName())
                .description(request.getDescription())
                .active(request.getActive())
                .build();

        RoleResponse role = manageRoleUseCase.updateRole(command);

        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete role (soft delete)")
    @PreAuthorize("@rbac.hasPermission('role:delete')")
    public ResponseEntity<Void> deleteRole(@PathVariable String id) {
        log.info("DELETE /api/v1/roles/{} - Delete role", id);

        manageRoleUseCase.deleteRole(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{roleId}/permissions/{permissionId}")
    @Operation(summary = "Assign permission to role")
    @PreAuthorize("@rbac.hasPermission('role:update')")
    public ResponseEntity<Void> assignPermission(
            @PathVariable String roleId,
            @PathVariable String permissionId) {
        log.info("POST /api/v1/roles/{}/permissions/{} - Assign permission", roleId, permissionId);

        AssignPermissionCommand command = AssignPermissionCommand.builder()
                .roleId(roleId)
                .permissionId(permissionId)
                .build();

        manageRoleUseCase.assignPermissionToRole(command);

        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{roleId}/permissions/{permissionId}")
    @Operation(summary = "Revoke permission from role")
    @PreAuthorize("@rbac.hasPermission('role:update')")
    public ResponseEntity<Void> revokePermission(
            @PathVariable String roleId,
            @PathVariable String permissionId) {
        log.info("DELETE /api/v1/roles/{}/permissions/{} - Revoke permission", roleId, permissionId);

        RevokePermissionCommand command = RevokePermissionCommand.builder()
                .roleId(roleId)
                .permissionId(permissionId)
                .build();

        manageRoleUseCase.revokePermissionFromRole(command);

        return ResponseEntity.noContent().build();
    }
}
