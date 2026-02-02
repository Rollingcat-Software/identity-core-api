package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.ManageUserUseCase;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.dto.ChangePasswordRequest;
import com.fivucsas.identity.dto.CreateUserRequest;
import com.fivucsas.identity.dto.UpdateUserRequest;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.dto.UserDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * REST controller for user management endpoints.
 *
 * Refactored to use Hexagonal Architecture input ports (use cases).
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "User CRUD operations")
public class UserController {

    private final ManageUserUseCase manageUserUseCase;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping
    @Operation(summary = "Get all users")
    @PreAuthorize("@rbac.hasPermission('user:read')")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        log.info("GET /api/v1/users - Get all users");

        List<UserResponse> responses = manageUserUseCase.getAllUsers(new GetAllUsersQuery());

        List<UserDto> users = responses.stream()
            .map(this::mapToUserDto)
            .collect(Collectors.toList());

        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get user by ID")
    @PreAuthorize("@rbac.hasPermission('user:read') or @userSecurityService.isCurrentUser(#id)")
    public ResponseEntity<UserDto> getUserById(@PathVariable String id) {
        log.info("GET /api/v1/users/{} - Get user by ID", id);

        GetUserByIdQuery query = GetUserByIdQuery.builder()
            .userId(id)
            .build();

        UserResponse response = manageUserUseCase.getUserById(query);

        return ResponseEntity.ok(mapToUserDto(response));
    }

    @PostMapping
    @Operation(summary = "Create new user")
    @PreAuthorize("@rbac.hasPermission('user:create')")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody CreateUserRequest request) {
        log.info("POST /api/v1/users - Create user: {}", request.getEmail());

        CreateUserCommand command = CreateUserCommand.builder()
            .email(request.getEmail())
            .password(request.getPassword())
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .phoneNumber(request.getPhoneNumber())
            .address(request.getAddress())
            .idNumber(request.getIdNumber())
            .build();

        UserResponse response = manageUserUseCase.createUser(command);

        return ResponseEntity.status(HttpStatus.CREATED).body(mapToUserDto(response));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update user")
    @PreAuthorize("@rbac.hasPermission('user:update') or @userSecurityService.isCurrentUser(#id)")
    public ResponseEntity<UserDto> updateUser(
            @PathVariable String id,
            @Valid @RequestBody UpdateUserRequest request) {
        log.info("PUT /api/v1/users/{} - Update user", id);

        UpdateUserCommand command = UpdateUserCommand.builder()
            .userId(id)
            .firstName(request.getFirstName())
            .lastName(request.getLastName())
            .phoneNumber(request.getPhoneNumber())
            .address(request.getAddress())
            .build();

        UserResponse response = manageUserUseCase.updateUser(command);

        return ResponseEntity.ok(mapToUserDto(response));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete user")
    @PreAuthorize("@rbac.hasPermission('user:delete')")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        log.info("DELETE /api/v1/users/{} - Delete user", id);

        manageUserUseCase.deleteUser(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/change-password")
    @Operation(summary = "Change user password")
    @PreAuthorize("hasAuthority('user:update') or @userSecurityService.isCurrentUser(#id)")
    public ResponseEntity<Void> changePassword(
            @PathVariable String id,
            @Valid @RequestBody ChangePasswordRequest request) {
        log.info("POST /api/v1/users/{}/change-password", id);

        java.util.UUID uuid = java.util.UUID.fromString(id);
        User user = userRepository.findById(uuid)
                .orElseThrow(() -> new UserNotFoundException(id));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        user.updatePassword(request.getNewPassword(), passwordEncoder);
        userRepository.save(user);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/search")
    @Operation(summary = "Search users")
    @PreAuthorize("@rbac.hasPermission('user:read')")
    public ResponseEntity<List<UserDto>> searchUsers(@RequestParam String query) {
        log.info("GET /api/v1/users/search?query={} - Search users", query);

        SearchUsersQuery searchQuery = SearchUsersQuery.builder()
            .searchQuery(query)
            .build();

        List<UserResponse> responses = manageUserUseCase.searchUsers(searchQuery);

        List<UserDto> users = responses.stream()
            .map(this::mapToUserDto)
            .collect(Collectors.toList());

        return ResponseEntity.ok(users);
    }

    private UserDto mapToUserDto(UserResponse response) {
        return UserDto.builder()
            .id(response.getId())
            .email(response.getEmail())
            .firstName(response.getFirstName())
            .lastName(response.getLastName())
            .phoneNumber(response.getPhoneNumber())
            .address(response.getAddress())
            .idNumber(response.getIdNumber())
            .status(UserStatus.valueOf(response.getStatus()))
            .role(response.getRole())
            .roles(response.getRoles())
            .tenantId(response.getTenantId())
            .isBiometricEnrolled(response.isBiometricEnrolled())
            .enrolledAt(response.getEnrolledAt())
            .lastVerifiedAt(response.getLastVerifiedAt())
            .verificationCount(response.getVerificationCount())
            .createdAt(response.getCreatedAt())
            .updatedAt(response.getUpdatedAt())
            .build();
    }
}
