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
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.repository.RoleRepository;
import com.fivucsas.identity.repository.UserRoleRepository;
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
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;

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

        log.info("Role {} assigned to user {} successfully", roleId, userId);
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
