package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.InvalidEmailException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.service.RefreshTokenService;
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
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RegisterUserService Tests")
class RegisterUserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoderPort passwordEncoder;

    @Mock
    private TokenGenerationPort tokenGenerator;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private RegisterUserService registerUserService;

    private RegisterUserCommand validCommand;
    private User savedUser;
    private RefreshToken refreshToken;

    @BeforeEach
    void setUp() {
        validCommand = RegisterUserCommand.builder()
            .email("test@example.com")
            .password("Password123!")
            .firstName("John")
            .lastName("Doe")
            .ipAddress("192.168.1.1")
            .userAgent("Mozilla/5.0")
            .build();

        savedUser = User.builder()
            .id(UUID.randomUUID())
            .email("test@example.com")
            .passwordHash("hashedPassword123")
            .firstName("John")
            .lastName("Doe")
            .status(UserStatus.ACTIVE)
            .isBiometricEnrolled(false)
            .verificationCount(0)
            .createdAt(Instant.now())
            .updatedAt(Instant.now())
            .build();

        refreshToken = RefreshToken.builder()
            .id(UUID.randomUUID())
            .token("refresh-token-value")
            .user(savedUser)
            .expiryDate(Instant.now().plus(Duration.ofDays(7)))
            .build();
    }

    @Nested
    @DisplayName("Successful Registration")
    class SuccessfulRegistration {

        @Test
        @DisplayName("Should register user successfully with valid command")
        void shouldRegisterUserSuccessfully() {
            // Given
            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn("hashedPassword123");
            when(userRepository.save(any(User.class))).thenReturn(savedUser);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(eq(savedUser), eq("192.168.1.1"), eq("Mozilla/5.0")))
                .thenReturn(refreshToken);

            // When
            AuthenticationResponse response = registerUserService.execute(validCommand);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            assertThat(response.getRefreshToken()).isEqualTo("refresh-token-value");
            assertThat(response.getUser()).isNotNull();
            assertThat(response.getUser().getEmail()).isEqualTo("test@example.com");
            assertThat(response.getUser().getFirstName()).isEqualTo("John");
            assertThat(response.getUser().getLastName()).isEqualTo("Doe");
            assertThat(response.getUser().getStatus()).isEqualTo("ACTIVE");

            verify(userRepository).existsByEmail("test@example.com");
            verify(passwordEncoder).encode("Password123!");
            verify(userRepository).save(any(User.class));
            verify(tokenGenerator).generateAccessToken("test@example.com");
            verify(refreshTokenService).createRefreshToken(savedUser, "192.168.1.1", "Mozilla/5.0");
        }

        @Test
        @DisplayName("Should create user with correct attributes")
        void shouldCreateUserWithCorrectAttributes() {
            // Given
            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn("hashedPassword123");
            when(userRepository.save(any(User.class))).thenReturn(savedUser);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // When
            registerUserService.execute(validCommand);

            // Then
            verify(userRepository).save(userCaptor.capture());
            User capturedUser = userCaptor.getValue();

            assertThat(capturedUser.getEmail()).isEqualTo("test@example.com");
            assertThat(capturedUser.getPasswordHash()).isEqualTo("hashedPassword123");
            assertThat(capturedUser.getFirstName()).isEqualTo("John");
            assertThat(capturedUser.getLastName()).isEqualTo("Doe");
            assertThat(capturedUser.getStatus()).isEqualTo(UserStatus.ACTIVE);
            assertThat(capturedUser.isBiometricEnrolled()).isFalse();
            assertThat(capturedUser.getVerificationCount()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Registration Failures")
    class RegistrationFailures {

        @Test
        @DisplayName("Should throw DuplicateEmailException when email exists")
        void shouldThrowDuplicateEmailExceptionWhenEmailExists() {
            // Given
            when(userRepository.existsByEmail("test@example.com")).thenReturn(true);

            // When/Then
            assertThatThrownBy(() -> registerUserService.execute(validCommand))
                .isInstanceOf(DuplicateEmailException.class)
                .hasMessageContaining("test@example.com");

            verify(userRepository).existsByEmail("test@example.com");
            verify(userRepository, never()).save(any());
            verify(tokenGenerator, never()).generateAccessToken(any());
        }

        @Test
        @DisplayName("Should throw InvalidEmailException for invalid email format")
        void shouldThrowInvalidEmailExceptionForInvalidEmail() {
            // Given
            RegisterUserCommand invalidEmailCommand = RegisterUserCommand.builder()
                .email("invalid-email")
                .password("Password123!")
                .firstName("John")
                .lastName("Doe")
                .build();

            when(userRepository.existsByEmail("invalid-email")).thenReturn(false);

            // When/Then
            assertThatThrownBy(() -> registerUserService.execute(invalidEmailCommand))
                .isInstanceOf(InvalidEmailException.class);

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw exception for empty first name")
        void shouldThrowExceptionForEmptyFirstName() {
            // Given
            RegisterUserCommand emptyNameCommand = RegisterUserCommand.builder()
                .email("test@example.com")
                .password("Password123!")
                .firstName("")
                .lastName("Doe")
                .build();

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

            // When/Then
            assertThatThrownBy(() -> registerUserService.execute(emptyNameCommand))
                .isInstanceOf(IllegalArgumentException.class);

            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw exception for null last name")
        void shouldThrowExceptionForNullLastName() {
            // Given
            RegisterUserCommand nullNameCommand = RegisterUserCommand.builder()
                .email("test@example.com")
                .password("Password123!")
                .firstName("John")
                .lastName(null)
                .build();

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

            // When/Then
            assertThatThrownBy(() -> registerUserService.execute(nullNameCommand))
                .isInstanceOf(IllegalArgumentException.class);

            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle null IP address and user agent")
        void shouldHandleNullIpAddressAndUserAgent() {
            // Given
            RegisterUserCommand commandWithNulls = RegisterUserCommand.builder()
                .email("test@example.com")
                .password("Password123!")
                .firstName("John")
                .lastName("Doe")
                .ipAddress(null)
                .userAgent(null)
                .build();

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn("hashedPassword123");
            when(userRepository.save(any(User.class))).thenReturn(savedUser);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(eq(savedUser), isNull(), isNull()))
                .thenReturn(refreshToken);

            // When
            AuthenticationResponse response = registerUserService.execute(commandWithNulls);

            // Then
            assertThat(response).isNotNull();
            verify(refreshTokenService).createRefreshToken(savedUser, null, null);
        }

        @Test
        @DisplayName("Should handle special characters in name")
        void shouldHandleSpecialCharactersInName() {
            // Given
            RegisterUserCommand specialNameCommand = RegisterUserCommand.builder()
                .email("test@example.com")
                .password("Password123!")
                .firstName("José-María")
                .lastName("O'Connor")
                .build();

            User userWithSpecialName = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash("hashedPassword123")
                .firstName("José-María")
                .lastName("O'Connor")
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn("hashedPassword123");
            when(userRepository.save(any(User.class))).thenReturn(userWithSpecialName);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            // When
            AuthenticationResponse response = registerUserService.execute(specialNameCommand);

            // Then
            assertThat(response.getUser().getFirstName()).isEqualTo("José-María");
            assertThat(response.getUser().getLastName()).isEqualTo("O'Connor");
        }
    }
}
