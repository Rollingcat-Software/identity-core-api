package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.*;
import com.fivucsas.identity.application.dto.query.*;
import com.fivucsas.identity.application.dto.response.PermissionResponse;
import com.fivucsas.identity.application.dto.response.RoleResponse;
import com.fivucsas.identity.application.dto.response.UserRoleResponse;
import com.fivucsas.identity.application.port.input.ManagePermissionUseCase;
import com.fivucsas.identity.application.port.input.ManageRoleUseCase;
import com.fivucsas.identity.application.port.input.ManageUserRoleUseCase;
import com.fivucsas.identity.dto.AssignRoleRequest;
import com.fivucsas.identity.dto.CreateRoleRequest;
import com.fivucsas.identity.dto.UpdateRoleRequest;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.UserSecurityService;
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
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Role Management", description = "Role CRUD and permission assignment operations")
public class RoleController {

    private final ManageRoleUseCase manageRoleUseCase;
    private final ManageUserRoleUseCase manageUserRoleUseCase;
    private final ManagePermissionUseCase managePermissionUseCase;
    private final UserSecurityService userSecurityService;
    private final RbacAuthorizationService rbacService;

    @GetMapping("/api/v1/roles")
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

    @GetMapping("/api/v1/roles/{id}")
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

    @GetMapping("/api/v1/roles/tenant/{tenantId}")
    @Operation(summary = "Get roles by tenant")
    @PreAuthorize("@rbac.hasPermission('role:read') and @rbac.canAccessTenant(#tenantId)")
    public ResponseEntity<List<RoleResponse>> getRolesByTenant(@PathVariable String tenantId) {
        log.info("GET /api/v1/roles/tenant/{} - Get roles by tenant", tenantId);

        GetRolesByTenantQuery query = GetRolesByTenantQuery.builder()
                .tenantId(tenantId)
                .build();

        List<RoleResponse> roles = manageRoleUseCase.getRolesByTenant(query);

        return ResponseEntity.ok(roles);
    }

    @PostMapping("/api/v1/roles")
    @Operation(summary = "Create new role")
    @PreAuthorize("@rbac.hasPermission('role:create') and @rbac.canAccessTenant(#request.tenantId)")
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

    @PutMapping("/api/v1/roles/{id}")
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

    @DeleteMapping("/api/v1/roles/{id}")
    @Operation(summary = "Delete role (soft delete)")
    @PreAuthorize("@rbac.hasPermission('role:delete')")
    public ResponseEntity<Void> deleteRole(@PathVariable String id) {
        log.info("DELETE /api/v1/roles/{} - Delete role", id);

        manageRoleUseCase.deleteRole(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/api/v1/roles/{roleId}/permissions/{permissionId}")
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

        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/api/v1/roles/{roleId}/permissions/{permissionId}")
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

    // --- User-Role endpoints merged from UserRoleController ---

    @GetMapping("/api/v1/users/{userId}/roles")
    @Operation(summary = "Get all roles for a user")
    @PreAuthorize("@rbac.hasPermission('user_role:read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<List<UserRoleResponse>> getUserRoles(@PathVariable String userId) {
        log.info("GET /api/v1/users/{}/roles - Get user roles", userId);

        GetUserRolesQuery query = GetUserRolesQuery.builder()
                .userId(userId)
                .build();

        return ResponseEntity.ok(manageUserRoleUseCase.getUserRoles(query));
    }

    @PostMapping("/api/v1/users/{userId}/roles/{roleId}")
    @Operation(summary = "Assign a role to a user")
    // SECURITY (2026-06-01, LOGIC_AUDIT P0-3): was @rbac.hasPermission('user_role:assign')
    // — which a TENANT_ADMIN holds implicitly with NO role-id ceiling, so they could
    // assign the global ROOT role and escalate. canAssignRole enforces the real ceiling
    // (own-tenant roles only for non-ROOT; global ROOT/SYSTEM are ROOT-only).
    @PreAuthorize("@rbac.canAssignRole(#roleId)")
    public ResponseEntity<Void> assignRole(
            @PathVariable String userId,
            @PathVariable String roleId,
            @Valid @RequestBody(required = false) AssignRoleRequest request) {
        log.info("POST /api/v1/users/{}/roles/{} - Assign role", userId, roleId);

        String currentUserId = userSecurityService.getCurrentUserId();

        AssignRoleToUserCommand command = AssignRoleToUserCommand.builder()
                .userId(userId)
                .roleId(roleId)
                .assignedBy(currentUserId)
                .expiresAt(request != null ? request.getExpiresAt() : null)
                .build();

        manageUserRoleUseCase.assignRoleToUser(command);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @DeleteMapping("/api/v1/users/{userId}/roles/{roleId}")
    @Operation(summary = "Revoke a role from a user")
    @PreAuthorize("@rbac.hasPermission('user_role:revoke')")
    public ResponseEntity<Void> revokeRole(
            @PathVariable String userId,
            @PathVariable String roleId) {
        log.info("DELETE /api/v1/users/{}/roles/{} - Revoke role", userId, roleId);

        RevokeRoleFromUserCommand command = RevokeRoleFromUserCommand.builder()
                .userId(userId)
                .roleId(roleId)
                .build();

        manageUserRoleUseCase.revokeRoleFromUser(command);

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/api/v1/users/{userId}/roles/all/{roleId}")
    @Operation(summary = "Get all users with a specific role")
    @PreAuthorize("@rbac.hasPermission('user_role:read')")
    public ResponseEntity<List<UserRoleResponse>> getRoleUsers(@PathVariable String roleId) {
        log.info("GET /api/v1/users/*/roles/all/{} - Get role users", roleId);

        GetRoleUsersQuery query = GetRoleUsersQuery.builder()
                .roleId(roleId)
                .build();

        return ResponseEntity.ok(manageUserRoleUseCase.getRoleUsers(query));
    }

    // --- Permission endpoints merged from PermissionController ---

    @GetMapping("/api/v1/permissions")
    @Operation(summary = "Get all permissions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<PermissionResponse>> getAllPermissions() {
        log.info("GET /api/v1/permissions - Get all permissions");
        // Enumerating ALL system-wide permissions is a ROOT operation.
        // For non-ROOT callers we return an empty list so the dashboard
        // renders (rather than 403'ing and breaking the page). No data leak —
        // permission metadata is only visible to the platform owner.
        if (!rbacService.isRoot()) {
            return ResponseEntity.ok(List.of());
        }
        return ResponseEntity.ok(managePermissionUseCase.getAllPermissions());
    }

    @GetMapping("/api/v1/permissions/{id}")
    @Operation(summary = "Get permission by ID")
    @PreAuthorize("@rbac.hasPermission('permission:read')")
    public ResponseEntity<PermissionResponse> getPermissionById(@PathVariable String id) {
        log.info("GET /api/v1/permissions/{} - Get permission by ID", id);

        GetPermissionByIdQuery query = GetPermissionByIdQuery.builder()
                .permissionId(id)
                .build();

        return ResponseEntity.ok(managePermissionUseCase.getPermissionById(query));
    }

    @GetMapping("/api/v1/permissions/resource/{resource}")
    @Operation(summary = "Get permissions by resource")
    @PreAuthorize("@rbac.hasPermission('permission:read')")
    public ResponseEntity<List<PermissionResponse>> getPermissionsByResource(@PathVariable String resource) {
        log.info("GET /api/v1/permissions/resource/{} - Get permissions by resource", resource);
        return ResponseEntity.ok(managePermissionUseCase.getPermissionsByResource(resource));
    }
}
