package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("GetCurrentUserService Tests")
class GetCurrentUserServiceTest {

    // Valid BCrypt hash for testing
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private GetCurrentUserService getCurrentUserService;

    private User existingUser;
    private GetUserByEmailQuery validQuery;

    @BeforeEach
    void setUp() {
        existingUser = User.builder()
            .id(UUID.randomUUID())
            .email("test@example.com")
            .passwordHash(VALID_BCRYPT_HASH)
            .firstName("John")
            .lastName("Doe")
            .phoneNumber("+1234567890")
            .address("123 Main St")
            .idNumber("12345678901")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(true)
            .verificationCount(5)
            .enrolledAt(Instant.now().minus(Duration.ofDays(10)))
            .lastVerifiedAt(Instant.now().minus(Duration.ofDays(1)))
            .createdAt(Instant.now().minus(Duration.ofDays(30)))
            .updatedAt(Instant.now())
            .build();

        validQuery = GetUserByEmailQuery.builder()
            .email("test@example.com")
            .build();
    }

    @Nested
    @DisplayName("Successful Get Current User")
    class SuccessfulGetCurrentUser {

        @Test
        @DisplayName("Should return user successfully when found")
        void shouldReturnUserSuccessfully() {
            // Given
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));

            // When
            UserResponse response = getCurrentUserService.execute(validQuery);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getId()).isEqualTo(existingUser.getId().toString());
            assertThat(response.getEmail()).isEqualTo("test@example.com");
            assertThat(response.getFirstName()).isEqualTo("John");
            assertThat(response.getLastName()).isEqualTo("Doe");
            assertThat(response.getPhoneNumber()).isEqualTo("+1234567890");
            assertThat(response.getAddress()).isEqualTo("123 Main St");
            assertThat(response.getStatus()).isEqualTo("ACTIVE");
            assertThat(response.isBiometricEnrolled()).isTrue();
            assertThat(response.getVerificationCount()).isEqualTo(5);

            verify(userRepository).findByEmail("test@example.com");
        }

        @Test
        @DisplayName("Should return masked ID number")
        void shouldReturnMaskedIdNumber() {
            // Given
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));

            // When
            UserResponse response = getCurrentUserService.execute(validQuery);

            // Then
            assertThat(response.getIdNumber()).isNotNull();
            // ID number should be masked (not showing full value)
            assertThat(response.getIdNumber()).contains("*");
        }

        @Test
        @DisplayName("Should return all timestamp fields")
        void shouldReturnAllTimestampFields() {
            // Given
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));

            // When
            UserResponse response = getCurrentUserService.execute(validQuery);

            // Then
            assertThat(response.getEnrolledAt()).isNotNull();
            assertThat(response.getLastVerifiedAt()).isNotNull();
            assertThat(response.getCreatedAt()).isNotNull();
            assertThat(response.getUpdatedAt()).isNotNull();
        }
    }

    @Nested
    @DisplayName("Get Current User Failures")
    class GetCurrentUserFailures {

        @Test
        @DisplayName("Should throw UserNotFoundException when user not found")
        void shouldThrowUserNotFoundExceptionWhenUserNotFound() {
            // Given
            when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

            GetUserByEmailQuery query = GetUserByEmailQuery.builder()
                .email("nonexistent@example.com")
                .build();

            // When/Then
            assertThatThrownBy(() -> getCurrentUserService.execute(query))
                .isInstanceOf(UserNotFoundException.class)
                .hasMessageContaining("nonexistent@example.com");

            verify(userRepository).findByEmail("nonexistent@example.com");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle user with null optional fields")
        void shouldHandleUserWithNullOptionalFields() {
            // Given
            User userWithNulls = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .phoneNumber(null)
                .address(null)
                .idNumber(null)
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .enrolledAt(null)
                .lastVerifiedAt(null)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(userWithNulls));

            // When
            UserResponse response = getCurrentUserService.execute(validQuery);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getPhoneNumber()).isNull();
            assertThat(response.getAddress()).isNull();
            assertThat(response.getIdNumber()).isNull();
            assertThat(response.getEnrolledAt()).isNull();
            assertThat(response.getLastVerifiedAt()).isNull();
        }

        @Test
        @DisplayName("Should handle different user statuses")
        void shouldHandleDifferentUserStatuses() {
            // Given
            User suspendedUser = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.SUSPENDED)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(suspendedUser));

            // When
            UserResponse response = getCurrentUserService.execute(validQuery);

            // Then
            assertThat(response.getStatus()).isEqualTo("SUSPENDED");
        }
    }
}
