package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.Role;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserRole;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.entity.UserType;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ManageUserService Tests")
class ManageUserServiceTest {

    // Valid BCrypt hash for testing
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoderPort passwordEncoder;

    @Mock
    private TenantScopeResolver tenantScopeResolver;

    @Mock
    private com.fivucsas.identity.application.port.output.AuditLogPort auditLogPort;

    @Mock
    private RbacAuthorizationService rbacService;

    @Mock
    private RoleRepositoryPort roleRepository;

    @Mock
    private UserRoleRepositoryPort userRoleRepository;

    @InjectMocks
    private ManageUserService manageUserService;

    private User existingUser;
    private UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        existingUser = User.builder()
            .id(userId)
            .email("test@example.com")
            .passwordHash(VALID_BCRYPT_HASH)
            .firstName("John")
            .lastName("Doe")
            .phoneNumber("+1234567890")
            .address("123 Main St")
            .idNumber("12345678901")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();
    }

    @Nested
    @DisplayName("Create User Tests")
    class CreateUserTests {

        @Test
        @DisplayName("Should create user successfully")
        void shouldCreateUserSuccessfully() {
            // Given
            CreateUserCommand command = CreateUserCommand.builder()
                .email("newuser@example.com")
                .password("Password123!")
                .firstName("Jane")
                .lastName("Smith")
                .phoneNumber("+0987654321")
                .address("456 Oak Ave")
                .idNumber("98765432109")
                .build();

            User savedUser = User.builder()
                .id(UUID.randomUUID())
                .email("newuser@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("Jane")
                .lastName("Smith")
                .phoneNumber("+0987654321")
                .address("456 Oak Ave")
                .idNumber("98765432109")
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.existsByEmail("newuser@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn(VALID_BCRYPT_HASH);
            when(userRepository.save(any(User.class))).thenReturn(savedUser);

            // When
            UserResponse response = manageUserService.createUser(command);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getEmail()).isEqualTo("newuser@example.com");
            assertThat(response.getFirstName()).isEqualTo("Jane");
            assertThat(response.getLastName()).isEqualTo("Smith");
            assertThat(response.getStatus()).isEqualTo("ACTIVE");

            verify(userRepository).existsByEmail("newuser@example.com");
            verify(passwordEncoder).encode("Password123!");
            verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("Should throw DuplicateEmailException when email exists")
        void shouldThrowDuplicateEmailExceptionWhenEmailExists() {
            // Given
            CreateUserCommand command = CreateUserCommand.builder()
                .email("existing@example.com")
                .password("Password123!")
                .firstName("Jane")
                .lastName("Smith")
                .build();

            when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

            // When/Then
            assertThatThrownBy(() -> manageUserService.createUser(command))
                .isInstanceOf(DuplicateEmailException.class);

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should create user with correct initial values")
        void shouldCreateUserWithCorrectInitialValues() {
            // Given
            CreateUserCommand command = CreateUserCommand.builder()
                .email("newuser@example.com")
                .password("Password123!")
                .firstName("Jane")
                .lastName("Smith")
                .build();

            when(userRepository.existsByEmail("newuser@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn(VALID_BCRYPT_HASH);
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                // Simulate database assigning an ID
                return User.builder()
                    .id(UUID.randomUUID())
                    .email(user.getEmail())
                    .passwordHash(user.getPasswordHash())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .status(user.getStatus())
                    .isBiometricEnrolled(user.isBiometricEnrolled())
                    .verificationCount(user.getVerificationCount())
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();
            });

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // When
            manageUserService.createUser(command);

            // Then
            verify(userRepository).save(userCaptor.capture());
            User capturedUser = userCaptor.getValue();

            assertThat(capturedUser.getStatus()).isEqualTo(UserStatus.ACTIVE);
            assertThat(capturedUser.isBiometricEnrolled()).isFalse();
            assertThat(capturedUser.getVerificationCount()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Get User By ID Tests")
    class GetUserByIdTests {

        @Test
        @DisplayName("Should get user by ID successfully")
        void shouldGetUserByIdSuccessfully() {
            // Given
            GetUserByIdQuery query = GetUserByIdQuery.builder()
                .userId(userId.toString())
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));

            // When
            UserResponse response = manageUserService.getUserById(query);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getId()).isEqualTo(userId.toString());
            assertThat(response.getEmail()).isEqualTo("test@example.com");

            verify(userRepository).findById(userId);
        }

        @Test
        @DisplayName("Should throw UserNotFoundException when user not found")
        void shouldThrowUserNotFoundExceptionWhenUserNotFound() {
            // Given
            UUID nonExistentId = UUID.randomUUID();
            GetUserByIdQuery query = GetUserByIdQuery.builder()
                .userId(nonExistentId.toString())
                .build();

            when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> manageUserService.getUserById(query))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining(nonExistentId.toString());
        }

        @Test
        @DisplayName("Should throw exception for invalid UUID format")
        void shouldThrowExceptionForInvalidUuidFormat() {
            // Given
            GetUserByIdQuery query = GetUserByIdQuery.builder()
                .userId("invalid-uuid")
                .build();

            // When/Then
            assertThatThrownBy(() -> manageUserService.getUserById(query))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("Get All Users Tests")
    class GetAllUsersTests {

        @Test
        @DisplayName("Should get all users successfully")
        void shouldGetAllUsersSuccessfully() {
            // Given
            User user2 = User.builder()
                .id(UUID.randomUUID())
                .email("user2@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("Jane")
                .lastName("Smith")
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.findAll(0, 20)).thenReturn(Arrays.asList(existingUser, user2));

            // When
            List<UserResponse> responses = manageUserService.getAllUsers(new GetAllUsersQuery());

            // Then
            assertThat(responses).hasSize(2);
            assertThat(responses.get(0).getEmail()).isEqualTo("test@example.com");
            assertThat(responses.get(1).getEmail()).isEqualTo("user2@example.com");

            verify(userRepository).findAll(0, 20);
        }

        @Test
        @DisplayName("Should return empty list when no users")
        void shouldReturnEmptyListWhenNoUsers() {
            // Given
            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.findAll(0, 20)).thenReturn(Collections.emptyList());

            // When
            List<UserResponse> responses = manageUserService.getAllUsers(new GetAllUsersQuery());

            // Then
            assertThat(responses).isEmpty();
        }
    }

    @Nested
    @DisplayName("Search Users Tests")
    class SearchUsersTests {

        @Test
        @DisplayName("Should search users successfully")
        void shouldSearchUsersSuccessfully() {
            // Given
            SearchUsersQuery query = SearchUsersQuery.builder()
                .searchQuery("john")
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.searchUsers("john")).thenReturn(Arrays.asList(existingUser));

            // When
            List<UserResponse> responses = manageUserService.searchUsers(query);

            // Then
            assertThat(responses).hasSize(1);
            assertThat(responses.get(0).getFirstName()).isEqualTo("John");

            verify(userRepository).searchUsers("john");
        }

        @Test
        @DisplayName("Should return empty list when no matches")
        void shouldReturnEmptyListWhenNoMatches() {
            // Given
            SearchUsersQuery query = SearchUsersQuery.builder()
                .searchQuery("nonexistent")
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.searchUsers("nonexistent")).thenReturn(Collections.emptyList());

            // When
            List<UserResponse> responses = manageUserService.searchUsers(query);

            // Then
            assertThat(responses).isEmpty();
        }
    }

    @Nested
    @DisplayName("Update User Tests")
    class UpdateUserTests {

        @Test
        @DisplayName("Should update user successfully")
        void shouldUpdateUserSuccessfully() {
            // Given
            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .firstName("Updated")
                .lastName("Name")
                .phoneNumber("+9999999999")
                .address("999 New St")
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(userRepository.save(any(User.class))).thenReturn(existingUser);

            // When
            UserResponse response = manageUserService.updateUser(command);

            // Then
            assertThat(response).isNotNull();
            verify(userRepository).findById(userId);
            verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("Should throw UserNotFoundException when updating non-existent user")
        void shouldThrowUserNotFoundExceptionWhenUpdatingNonExistentUser() {
            // Given
            UUID nonExistentId = UUID.randomUUID();
            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(nonExistentId.toString())
                .firstName("Updated")
                .lastName("Name")
                .build();

            when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> manageUserService.updateUser(command))
                .isInstanceOf(UserNotFoundException.class);

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should update only provided fields")
        void shouldUpdateOnlyProvidedFields() {
            // Given
            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .firstName("Updated")
                .lastName(null)
                .phoneNumber(null)
                .address(null)
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

            // When
            manageUserService.updateUser(command);

            // Then
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();

            assertThat(savedUser.getFirstName()).isEqualTo("Updated");
            // Other fields should remain unchanged
        }
    }

    @Nested
    @DisplayName("Delete User Tests")
    class DeleteUserTests {

        @Test
        @DisplayName("Should delete user successfully")
        void shouldDeleteUserSuccessfully() {
            // Given
            when(tenantScopeResolver.currentScope()).thenReturn(null);
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            doNothing().when(userRepository).delete(existingUser);

            // When
            manageUserService.deleteUser(userId.toString());

            // Then
            verify(userRepository).findById(userId);
            verify(userRepository).delete(existingUser);
        }

        @Test
        @DisplayName("Should throw UserNotFoundException when deleting non-existent user")
        void shouldThrowUserNotFoundExceptionWhenDeletingNonExistentUser() {
            // Given
            UUID nonExistentId = UUID.randomUUID();
            when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> manageUserService.deleteUser(nonExistentId.toString()))
                .isInstanceOf(UserNotFoundException.class);

            verify(userRepository, never()).delete(any());
        }
    }

    @Nested
    @DisplayName("Platform-tier (user_type) authorization")
    class UserTypeAuthorizationTests {

        /** Builds a user that belongs to {@code tenantId} so enforceTenantScope passes. */
        private User memberInTenant(UUID tenantId) {
            Tenant tenant = Tenant.builder().id(tenantId).name("Caller Tenant").build();
            return User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John").lastName("Doe")
                .status(UserStatus.ACTIVE)
                .tenant(tenant)
                .isBiometricEnrolled(false).verificationCount(0)
                .createdAt(Instant.now()).updatedAt(Instant.now())
                .build();
        }

        @Test
        @DisplayName("Non-ROOT caller cannot elevate a user's user_type → 403")
        void nonRootCannotElevateUserType() {
            // user defaults to TENANT_MEMBER; request elevation to ROOT.
            UUID callerTenant = UUID.randomUUID();
            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .userType("ROOT")
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
            when(userRepository.findById(userId)).thenReturn(Optional.of(memberInTenant(callerTenant)));
            when(rbacService.isRoot()).thenReturn(false);

            assertThatThrownBy(() -> manageUserService.updateUser(command))
                .isInstanceOf(UnauthorizedException.class);

            // Fail-closed: no persistence happened.
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("TENANT_ADMIN cannot self-elevate to TENANT_ADMIN tier on a member → 403")
        void tenantAdminCannotGrantTenantAdminTier() {
            UUID callerTenant = UUID.randomUUID();
            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .userType("TENANT_ADMIN")
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
            when(userRepository.findById(userId)).thenReturn(Optional.of(memberInTenant(callerTenant)));
            when(rbacService.isRoot()).thenReturn(false);

            assertThatThrownBy(() -> manageUserService.updateUser(command))
                .isInstanceOf(UnauthorizedException.class);

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("ROOT caller may change a user's user_type")
        void rootMayChangeUserType() {
            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .userType("TENANT_ADMIN")
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(null); // ROOT
            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(rbacService.isRoot()).thenReturn(true);
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            manageUserService.updateUser(command);

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            assertThat(captor.getValue().getUserType()).isEqualTo(UserType.TENANT_ADMIN);
        }

        @Test
        @DisplayName("No-op user_type (equal to current) is allowed for a non-ROOT caller")
        void noOpUserTypeAllowedForNonRoot() {
            // user is TENANT_MEMBER; requesting the same tier must not 403.
            UUID callerTenant = UUID.randomUUID();
            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .userType("TENANT_MEMBER")
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
            when(userRepository.findById(userId)).thenReturn(Optional.of(memberInTenant(callerTenant)));
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            manageUserService.updateUser(command);

            // rbacService.isRoot() must NOT even be consulted for a no-op tier.
            verify(rbacService, never()).isRoot();
            verify(userRepository).save(any(User.class));
        }
    }

    @Nested
    @DisplayName("Within-tenant role assignment authorization")
    class RoleAssignmentAuthorizationTests {

        /** Builds a user that belongs to {@code tenantId} so enforceTenantScope passes. */
        private User memberInTenant(UUID tenantId) {
            Tenant tenant = Tenant.builder().id(tenantId).name("Caller Tenant").build();
            return User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John").lastName("Doe")
                .status(UserStatus.ACTIVE)
                .tenant(tenant)
                .isBiometricEnrolled(false).verificationCount(0)
                .createdAt(Instant.now()).updatedAt(Instant.now())
                .build();
        }

        @Test
        @DisplayName("TENANT_ADMIN cannot assign a role from another tenant → 403")
        void tenantAdminCannotAssignForeignTenantRole() {
            UUID callerTenant = UUID.randomUUID();
            UUID foreignTenant = UUID.randomUUID();
            UUID roleId = UUID.randomUUID();

            Tenant otherTenant = Tenant.builder().id(foreignTenant).name("Other").build();
            Role foreignRole = Role.builder()
                .id(roleId).name("EDITOR").tenant(otherTenant).build();

            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .roleIds(List.of(roleId))
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
            when(userRepository.findById(userId)).thenReturn(Optional.of(memberInTenant(callerTenant)));
            when(rbacService.isRoot()).thenReturn(false);
            when(userRoleRepository.findByIdUserId(userId)).thenReturn(Collections.emptyList());
            when(roleRepository.findById(roleId)).thenReturn(Optional.of(foreignRole));

            assertThatThrownBy(() -> manageUserService.updateUser(command))
                .isInstanceOf(UnauthorizedException.class);

            // Fail-closed: no assignment was persisted.
            verify(userRoleRepository, never()).save(any());
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("TENANT_ADMIN may assign a role from their own tenant")
        void tenantAdminMayAssignOwnTenantRole() {
            UUID callerTenant = UUID.randomUUID();
            UUID roleId = UUID.randomUUID();

            Tenant ownTenant = Tenant.builder().id(callerTenant).name("Own").build();
            Role ownRole = Role.builder()
                .id(roleId).name("EDITOR").tenant(ownTenant).build();

            UpdateUserCommand command = UpdateUserCommand.builder()
                .userId(userId.toString())
                .roleIds(List.of(roleId))
                .build();

            when(tenantScopeResolver.currentScope()).thenReturn(callerTenant);
            when(userRepository.findById(userId)).thenReturn(Optional.of(memberInTenant(callerTenant)));
            when(rbacService.isRoot()).thenReturn(false);
            when(userRoleRepository.findByIdUserId(userId)).thenReturn(Collections.emptyList());
            when(roleRepository.findById(roleId)).thenReturn(Optional.of(ownRole));
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            manageUserService.updateUser(command);

            ArgumentCaptor<UserRole> captor = ArgumentCaptor.forClass(UserRole.class);
            verify(userRoleRepository).save(captor.capture());
            assertThat(captor.getValue().getRoleId()).isEqualTo(roleId);
        }
    }
}
