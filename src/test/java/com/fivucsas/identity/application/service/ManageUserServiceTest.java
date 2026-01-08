package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.CreateUserCommand;
import com.fivucsas.identity.application.dto.command.UpdateUserCommand;
import com.fivucsas.identity.application.dto.query.GetAllUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserByIdQuery;
import com.fivucsas.identity.application.dto.query.SearchUsersQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
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

            when(userRepository.findAll()).thenReturn(Arrays.asList(existingUser, user2));

            // When
            List<UserResponse> responses = manageUserService.getAllUsers(new GetAllUsersQuery());

            // Then
            assertThat(responses).hasSize(2);
            assertThat(responses.get(0).getEmail()).isEqualTo("test@example.com");
            assertThat(responses.get(1).getEmail()).isEqualTo("user2@example.com");

            verify(userRepository).findAll();
        }

        @Test
        @DisplayName("Should return empty list when no users")
        void shouldReturnEmptyListWhenNoUsers() {
            // Given
            when(userRepository.findAll()).thenReturn(Collections.emptyList());

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
}
