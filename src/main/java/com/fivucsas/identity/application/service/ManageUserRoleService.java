package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AssignRoleToUserCommand;
import com.fivucsas.identity.application.dto.command.RevokeRoleFromUserCommand;
import com.fivucsas.identity.application.dto.query.GetRoleUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserRolesQuery;
import com.fivucsas.identity.application.dto.response.UserRoleResponse;
import com.fivucsas.identity.application.port.input.ManageUserRoleUseCase;
import com.fivucsas.identity.domain.exception.DuplicateRoleAssignmentException;
import com.fivucsas.identity.domain.exception.RoleNotFoundException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserTypeElevationPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for user-role assignment operations.
 *
 * Implements the ManageUserRoleUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageUserRoleService implements ManageUserRoleUseCase {

    private final UserRepository userRepository;
    private final RoleRepositoryPort roleRepository;
    private final UserRoleRepositoryPort userRoleRepository;
    private final UserTypeElevationPort userTypeElevationPort;

    @Override
    @Transactional
    public void assignRoleToUser(AssignRoleToUserCommand command) {
        log.info("Assigning role {} to user {}", command.getRoleId(), command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        UUID roleId = UUID.fromString(command.getRoleId());
        UUID assignedBy = command.getAssignedBy() != null ? UUID.fromString(command.getAssignedBy()) : null;

        // Verify user exists
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        // Verify role exists and is active
        Role role = roleRepository.findByIdWithPermissions(roleId)
                .orElseThrow(() -> new RoleNotFoundException(command.getRoleId()));

        // Check for duplicate assignment
        if (userRoleRepository.existsByIdUserIdAndIdRoleId(userId, roleId)) {
            throw new DuplicateRoleAssignmentException(command.getUserId(), command.getRoleId());
        }

        // Create the user-role assignment
        UserRole userRole = UserRole.create(user, role, assignedBy, command.getExpiresAt());
        userRoleRepository.save(userRole);

        // SECURITY (2026-06-01, LOGIC_AUDIT P0-3 — decouple user_type from role).
        // Role assignment is now TIER-NEUTRAL: it grants RBAC permissions only and NEVER
        // changes the platform tier (users.user_type). This previously called
        // userTypeElevationPort.elevateForGrantedRole(), so granting the ROOT role
        // promoted the target to user_type=ROOT — conflating the two orthogonal axes
        // (tier = trust, role = within-tenant permissions) and creating the escalation
        // surface, while ALSO disagreeing with the /users admin path (applyRoleIds), which
        // already keeps tier out. The platform tier is the SOLE authority and is set
        // EXPLICITLY via ManageUserService.applyUserType (the /users form's user_type
        // field). Decoupling removes the whole "role grant can escalate tier" class.
        // See docs/IDENTITY_ROLE_UNIFICATION.md.

        log.info("Role {} assigned to user {} (tier unchanged — user_type is set explicitly)", roleId, userId);
    }

    @Override
    @Transactional
    public void revokeRoleFromUser(RevokeRoleFromUserCommand command) {
        log.info("Revoking role {} from user {}", command.getRoleId(), command.getUserId());

        UUID userId = UUID.fromString(command.getUserId());
        UUID roleId = UUID.fromString(command.getRoleId());

        // Verify user exists
        if (userRepository.findById(userId).isEmpty()) {
            throw new UserNotFoundException(command.getUserId());
        }

        // Verify role exists
        if (roleRepository.findById(roleId).isEmpty()) {
            throw new RoleNotFoundException(command.getRoleId());
        }

        // Delete the assignment
        userRoleRepository.deleteByUserIdAndRoleId(userId, roleId);

        log.info("Role {} revoked from user {} successfully", roleId, userId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserRoleResponse> getUserRoles(GetUserRolesQuery query) {
        log.info("Fetching roles for user: {}", query.getUserId());

        UUID userId = UUID.fromString(query.getUserId());

        // Verify user exists
        if (userRepository.findById(userId).isEmpty()) {
            throw new UserNotFoundException(query.getUserId());
        }

        List<UserRole> userRoles = userRoleRepository.findByUserIdWithRole(userId);

        return userRoles.stream()
                .map(this::mapToUserRoleResponse)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserRoleResponse> getRoleUsers(GetRoleUsersQuery query) {
        log.info("Fetching users for role: {}", query.getRoleId());

        UUID roleId = UUID.fromString(query.getRoleId());

        // Verify role exists
        if (roleRepository.findById(roleId).isEmpty()) {
            throw new RoleNotFoundException(query.getRoleId());
        }

        List<UserRole> userRoles = userRoleRepository.findByRoleIdWithUser(roleId);

        return userRoles.stream()
                .map(this::mapToUserRoleResponse)
                .collect(Collectors.toList());
    }

    private UserRoleResponse mapToUserRoleResponse(UserRole userRole) {
        User user = userRole.getUser();
        Role role = userRole.getRole();

        String userName = null;
        String userEmail = null;
        if (user != null) {
            userName = user.getFirstName() + " " + user.getLastName();
            userEmail = user.getEmail();
        }

        return UserRoleResponse.builder()
                .userId(userRole.getUserId() != null ? userRole.getUserId().toString() : null)
                .userEmail(userEmail)
                .userName(userName)
                .roleId(userRole.getRoleId() != null ? userRole.getRoleId().toString() : null)
                .roleName(role != null ? role.getName() : null)
                .assignedAt(userRole.getAssignedAt())
                .assignedBy(userRole.getAssignedBy() != null ? userRole.getAssignedBy().toString() : null)
                .expiresAt(userRole.getExpiresAt())
                .expired(userRole.isExpired())
                .build();
    }
}
