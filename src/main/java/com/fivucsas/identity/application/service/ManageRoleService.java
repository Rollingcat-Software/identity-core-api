package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.*;
import com.fivucsas.identity.application.dto.query.*;
import com.fivucsas.identity.application.dto.response.PermissionResponse;
import com.fivucsas.identity.application.dto.response.RoleResponse;
import com.fivucsas.identity.application.port.input.ManageRoleUseCase;
import com.fivucsas.identity.domain.exception.*;
import com.fivucsas.identity.entity.Permission;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.application.port.output.PermissionRepositoryPort;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.repository.JpaTenantRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for role management (CRUD operations and permission assignment).
 *
 * Implements the ManageRoleUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageRoleService implements ManageRoleUseCase {

    private final RoleRepositoryPort roleRepository;
    private final PermissionRepositoryPort permissionRepository;
    private final JpaTenantRepository tenantRepository;

    @Override
    @Transactional
    public RoleResponse createRole(CreateRoleCommand command) {
        log.info("Creating new role: {}", command.getName());

        // Resolve tenant
        Tenant tenant = null;
        if (command.getTenantId() != null) {
            UUID tenantId = UUID.fromString(command.getTenantId());
            tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + command.getTenantId()));

            // Check for duplicate role name in same tenant
            if (roleRepository.existsByTenantIdAndNameAndDeletedAtIsNull(tenantId, command.getName())) {
                throw new DuplicateRoleException(command.getName());
            }
        }

        Role role = Role.builder()
                .tenant(tenant)
                .name(command.getName())
                .description(command.getDescription())
                .isSystemRole(command.isSystemRole())
                .active(true)
                .build();

        // Assign initial permissions if provided
        if (command.getPermissionIds() != null && !command.getPermissionIds().isEmpty()) {
            List<UUID> permissionUuids = command.getPermissionIds().stream()
                    .map(UUID::fromString)
                    .collect(Collectors.toList());
            List<Permission> permissions = permissionRepository.findByIdIn(permissionUuids);
            permissions.forEach(role::addPermission);
        }

        role = roleRepository.save(role);
        log.info("Role created successfully: {}", role.getId());

        return mapToRoleResponse(role);
    }

    @Override
    @Transactional(readOnly = true)
    public RoleResponse getRoleById(GetRoleByIdQuery query) {
        log.info("Fetching role by id: {}", query.getRoleId());

        UUID uuid = UUID.fromString(query.getRoleId());
        Role role = roleRepository.findByIdWithPermissions(uuid)
                .orElseThrow(() -> new RoleNotFoundException(query.getRoleId()));

        return mapToRoleResponse(role);
    }

    @Override
    @Transactional(readOnly = true)
    public List<RoleResponse> getAllRoles(GetAllRolesQuery query) {
        log.info("Fetching all roles, includeInactive={}", query.isIncludeInactive());

        List<Role> roles;
        if (query.isIncludeInactive()) {
            roles = roleRepository.findAllWithPermissions();
        } else {
            roles = roleRepository.findAllActiveWithPermissions();
        }

        return roles.stream()
                .map(this::mapToRoleResponse)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<RoleResponse> getRolesByTenant(GetRolesByTenantQuery query) {
        log.info("Fetching roles for tenant: {}", query.getTenantId());

        UUID tenantId = UUID.fromString(query.getTenantId());
        List<Role> roles = roleRepository.findByTenantIdWithPermissions(tenantId);

        return roles.stream()
                .map(this::mapToRoleResponse)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public RoleResponse updateRole(UpdateRoleCommand command) {
        log.info("Updating role: {}", command.getRoleId());

        UUID uuid = UUID.fromString(command.getRoleId());
        Role role = roleRepository.findByIdWithPermissions(uuid)
                .orElseThrow(() -> new RoleNotFoundException(command.getRoleId()));

        // Prevent modification of system roles
        if (role.isSystemRole()) {
            throw new SystemRoleModificationException(role.getName());
        }

        if (command.getName() != null) {
            role.updateName(command.getName());
        }

        if (command.getDescription() != null) {
            role.setDescription(command.getDescription());
        }

        if (command.getActive() != null) {
            if (command.getActive()) {
                role.activate();
            } else {
                role.deactivate();
            }
        }

        role = roleRepository.save(role);
        log.info("Role updated successfully: {}", role.getId());

        return mapToRoleResponse(role);
    }

    @Override
    @Transactional
    public void deleteRole(String roleId) {
        log.info("Deleting role: {}", roleId);

        UUID uuid = UUID.fromString(roleId);
        Role role = roleRepository.findById(uuid)
                .orElseThrow(() -> new RoleNotFoundException(roleId));

        // Prevent deletion of system roles
        if (role.isSystemRole()) {
            throw new SystemRoleModificationException(role.getName());
        }

        // Soft delete
        role.softDelete();
        roleRepository.save(role);
        log.info("Role soft-deleted successfully: {}", roleId);
    }

    @Override
    @Transactional
    public void assignPermissionToRole(AssignPermissionCommand command) {
        log.info("Assigning permission {} to role {}", command.getPermissionId(), command.getRoleId());

        UUID roleUuid = UUID.fromString(command.getRoleId());
        UUID permissionUuid = UUID.fromString(command.getPermissionId());

        Role role = roleRepository.findByIdWithPermissions(roleUuid)
                .orElseThrow(() -> new RoleNotFoundException(command.getRoleId()));

        // Prevent modification of system roles (except by system)
        if (role.isSystemRole()) {
            throw new SystemRoleModificationException(role.getName());
        }

        Permission permission = permissionRepository.findById(permissionUuid)
                .orElseThrow(() -> new PermissionNotFoundException(command.getPermissionId()));

        role.addPermission(permission);
        roleRepository.save(role);
        log.info("Permission assigned successfully to role: {}", role.getId());
    }

    @Override
    @Transactional
    public void revokePermissionFromRole(RevokePermissionCommand command) {
        log.info("Revoking permission {} from role {}", command.getPermissionId(), command.getRoleId());

        UUID roleUuid = UUID.fromString(command.getRoleId());
        UUID permissionUuid = UUID.fromString(command.getPermissionId());

        Role role = roleRepository.findByIdWithPermissions(roleUuid)
                .orElseThrow(() -> new RoleNotFoundException(command.getRoleId()));

        // Prevent modification of system roles
        if (role.isSystemRole()) {
            throw new SystemRoleModificationException(role.getName());
        }

        Permission permission = permissionRepository.findById(permissionUuid)
                .orElseThrow(() -> new PermissionNotFoundException(command.getPermissionId()));

        role.removePermission(permission);
        roleRepository.save(role);
        log.info("Permission revoked successfully from role: {}", role.getId());
    }

    private RoleResponse mapToRoleResponse(Role role) {
        List<PermissionResponse> permissionResponses = role.getPermissions().stream()
                .map(this::mapToPermissionResponse)
                .collect(Collectors.toList());

        return RoleResponse.builder()
                .id(role.getId().toString())
                .tenantId(role.getTenant() != null ? role.getTenant().getId().toString() : null)
                .name(role.getName())
                .description(role.getDescription())
                .systemRole(role.isSystemRole())
                .active(role.isActive())
                .permissions(permissionResponses)
                .createdAt(role.getCreatedAt())
                .updatedAt(role.getUpdatedAt())
                .build();
    }

    private PermissionResponse mapToPermissionResponse(Permission permission) {
        return PermissionResponse.builder()
                .id(permission.getId().toString())
                .name(permission.getName())
                .description(permission.getDescription())
                .resource(permission.getResource())
                .action(permission.getAction())
                .authority(permission.getAuthorityName())
                .build();
    }
}
