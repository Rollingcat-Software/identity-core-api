package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.ManageUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogQueryPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.TenantNotFoundException;
import com.fivucsas.identity.domain.exception.RoleNotFoundException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.model.user.*;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Use case service for user management (CRUD operations).
 *
 * Implements the ManageUserUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageUserService implements ManageUserUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoderPort passwordEncoder;
    private final JpaTenantRepository tenantRepository;
    private final RoleRepositoryPort roleRepository;
    private final UserRoleRepositoryPort userRoleRepository;
    private final AuditLogQueryPort auditLogQueryPort;

    @Override
    @Transactional
    public UserResponse createUser(CreateUserCommand command) {
        log.info("Creating new user: {}", command.getEmail());

        if (userRepository.existsByEmail(command.getEmail())) {
            throw new DuplicateEmailException(command.getEmail());
        }

        // Validate using value objects
        Email email = Email.of(command.getEmail());
        FullName fullName = FullName.of(command.getFirstName(), command.getLastName());
        HashedPassword hashedPassword = HashedPassword.of(passwordEncoder.encode(command.getPassword()));

        // Handle tenant assignment
        Tenant tenant = null;
        if (command.getTenantId() != null && !command.getTenantId().isEmpty()) {
            UUID tenantUuid = UUID.fromString(command.getTenantId());
            tenant = tenantRepository.findById(tenantUuid)
                .orElseThrow(() -> new TenantNotFoundException(command.getTenantId()));
        }

        User user = User.builder()
            .email(email.getValue())
            .passwordHash(hashedPassword.getValue())
            .firstName(fullName.getFirstName())
            .lastName(fullName.getLastName())
            .idNumber(command.getIdNumber())
            .phoneNumber(command.getPhoneNumber())
            .address(command.getAddress())
            .tenant(tenant)
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .build();

        user = userRepository.save(user);
        log.info("User created successfully: {}", user.getId());

        // Handle role assignment
        if (command.getRole() != null && !command.getRole().isEmpty()) {
            try {
                Role role;
                if (tenant != null) {
                    // Look for role within the user's tenant
                    role = roleRepository.findByTenantIdAndNameAndDeletedAtIsNull(tenant.getId(), command.getRole())
                        .orElseThrow(() -> new RoleNotFoundException(command.getRole()));
                } else {
                    // No tenant context — look up globally (only safe for unique system roles)
                    role = roleRepository.findByNameAndDeletedAtIsNull(command.getRole())
                        .orElseThrow(() -> new RoleNotFoundException(command.getRole()));
                }

                // Create user-role assignment
                UserRole userRole = UserRole.create(user, role, null, null);
                userRoleRepository.save(userRole);
                log.info("Role {} assigned to user {} during creation", command.getRole(), user.getId());
            } catch (RoleNotFoundException e) {
                log.warn("Role {} not found for user creation, skipping role assignment", command.getRole());
            }
        }

        return mapToUserResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(GetUserByIdQuery query) {
        log.info("Fetching user by id: {}", query.getUserId());

        UUID uuid = UUID.fromString(query.getUserId());
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(query.getUserId()));

        return enrichWithLoginInfo(mapToUserResponse(user));
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers(GetAllUsersQuery query) {
        log.info("Fetching all users (page={}, size={})", query.getPage(), query.getSize());

        return userRepository.findAll(query.getPage(), query.getSize()).stream()
            .map(this::mapToUserResponse)
            .map(this::enrichWithLoginInfo)
            .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> searchUsers(SearchUsersQuery query) {
        log.info("Searching users with query: {}", query.getSearchQuery());

        return userRepository.searchUsers(query.getSearchQuery()).stream()
            .map(this::mapToUserResponse)
            .map(this::enrichWithLoginInfo)
            .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public long countAllUsers() {
        return userRepository.count();
    }

    @Override
    @Transactional
    public UserResponse updateUser(UpdateUserCommand command) {
        log.info("Updating user: {}", command.getUserId());

        UUID uuid = UUID.fromString(command.getUserId());
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(command.getUserId()));

        // Use value objects for validation
        if (command.getFirstName() != null && command.getLastName() != null) {
            FullName fullName = FullName.of(command.getFirstName(), command.getLastName());
            user.setFirstName(fullName.getFirstName());
            user.setLastName(fullName.getLastName());
        } else {
            if (command.getFirstName() != null) {
                user.setFirstName(command.getFirstName());
            }
            if (command.getLastName() != null) {
                user.setLastName(command.getLastName());
            }
        }

        if (command.getPhoneNumber() != null) {
            PhoneNumber phone = PhoneNumber.ofNullable(command.getPhoneNumber());
            user.updatePhoneNumber(phone);
        }

        if (command.getAddress() != null) {
            Address address = Address.ofNullable(command.getAddress());
            user.updateAddress(address);
        }

        user = userRepository.save(user);
        log.info("User updated successfully: {}", user.getId());

        return mapToUserResponse(user);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        log.info("Deleting user: {}", userId);

        UUID uuid = UUID.fromString(userId);
        User user = userRepository.findById(uuid)
            .orElseThrow(() -> new UserNotFoundException(userId));

        userRepository.delete(user);
        log.info("User deleted successfully: {}", userId);
    }

    private UserResponse mapToUserResponse(User user) {
        return com.fivucsas.identity.application.mapper.UserResponseMapper.toResponse(user);
    }

    private UserResponse enrichWithLoginInfo(UserResponse response) {
        return response.toBuilder()
            .lastLoginAt(getLastLoginAt(response.getId()))
            .lastLoginIp(getLastLoginIp(response.getId()))
            .build();
    }

    private Instant getLastLoginAt(String userId) {
        try {
            var page = auditLogQueryPort.findByUserIdAndActionOrderByCreatedAtDesc(
                    UUID.fromString(userId), "USER_AUTHENTICATED",
                    PageRequest.of(0, 1));
            return page.hasContent() ? page.getContent().getFirst().getCreatedAt() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String getLastLoginIp(String userId) {
        try {
            var page = auditLogQueryPort.findByUserIdAndActionOrderByCreatedAtDesc(
                    UUID.fromString(userId), "USER_AUTHENTICATED",
                    PageRequest.of(0, 1));
            return page.hasContent() ? page.getContent().getFirst().getIpAddress() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
