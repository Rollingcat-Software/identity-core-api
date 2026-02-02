package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.AssignRoleToUserCommand;
import com.fivucsas.identity.application.dto.command.RevokeRoleFromUserCommand;
import com.fivucsas.identity.application.dto.query.GetRoleUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserRolesQuery;
import com.fivucsas.identity.application.dto.response.UserRoleResponse;
import com.fivucsas.identity.application.port.input.ManageUserRoleUseCase;
import com.fivucsas.identity.dto.AssignRoleRequest;
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
 * REST controller for user-role assignment endpoints.
 *
 * Manages the assignment and revocation of roles from users.
 */
@RestController
@RequestMapping("/api/v1/users/{userId}/roles")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Role Management", description = "User-role assignment operations")
public class UserRoleController {

    private final ManageUserRoleUseCase manageUserRoleUseCase;
    private final UserSecurityService userSecurityService;

    @GetMapping
    @Operation(summary = "Get all roles for a user")
    @PreAuthorize("@rbac.hasPermission('user_role:read') or @userSecurityService.isCurrentUser(#userId)")
    public ResponseEntity<List<UserRoleResponse>> getUserRoles(@PathVariable String userId) {
        log.info("GET /api/v1/users/{}/roles - Get user roles", userId);

        GetUserRolesQuery query = GetUserRolesQuery.builder()
                .userId(userId)
                .build();

        List<UserRoleResponse> userRoles = manageUserRoleUseCase.getUserRoles(query);

        return ResponseEntity.ok(userRoles);
    }

    @PostMapping("/{roleId}")
    @Operation(summary = "Assign a role to a user")
    @PreAuthorize("@rbac.hasPermission('user_role:assign')")
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

    @DeleteMapping("/{roleId}")
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

    @GetMapping("/all/{roleId}")
    @Operation(summary = "Get all users with a specific role")
    @PreAuthorize("@rbac.hasPermission('user_role:read')")
    public ResponseEntity<List<UserRoleResponse>> getRoleUsers(@PathVariable String roleId) {
        log.info("GET /api/v1/users/*/roles/all/{} - Get role users", roleId);

        GetRoleUsersQuery query = GetRoleUsersQuery.builder()
                .roleId(roleId)
                .build();

        List<UserRoleResponse> userRoles = manageUserRoleUseCase.getRoleUsers(query);

        return ResponseEntity.ok(userRoles);
    }
}
