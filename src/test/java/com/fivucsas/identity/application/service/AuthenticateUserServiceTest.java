package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.EventPublisherPort;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.AccountLockedException;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.service.RefreshTokenService;
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
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthenticateUserService Tests")
class AuthenticateUserServiceTest {

    // Valid BCrypt hash for testing
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoderPort passwordEncoder;

    @Mock
    private TokenGenerationPort tokenGenerator;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private AuditLogPort auditLogPort;

    @Mock
    private EventPublisherPort eventPublisher;

    @Mock
    private AuthFlowRepositoryPort authFlowRepository;

    @Mock
    private OAuth2ClientRepositoryPort oAuth2ClientRepository;

    @Mock
    private UserEnrollmentRepository userEnrollmentRepository;

    @Mock
    private MfaSessionRepository mfaSessionRepository;

    @Mock
    private EnrollmentHealthService enrollmentHealthService;

    @InjectMocks
    private AuthenticateUserService authenticateUserService;

    private AuthenticateUserCommand validCommand;
    private User existingUser;
    private RefreshToken refreshToken;

    @BeforeEach
    void setUp() {
        validCommand = AuthenticateUserCommand.builder()
            .email("test@example.com")
            .password("Password123!")
            .ipAddress("192.168.1.1")
            .userAgent("Mozilla/5.0")
            .build();

        existingUser = User.builder()
            .id(UUID.randomUUID())
            .email("test@example.com")
            .passwordHash(VALID_BCRYPT_HASH)
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
            .user(existingUser)
            .expiryDate(Instant.now().plus(Duration.ofDays(7)))
            .build();
    }

    @Nested
    @DisplayName("Successful Authentication")
    class SuccessfulAuthentication {

        @Test
        @DisplayName("Should authenticate user successfully with valid credentials")
        void shouldAuthenticateUserSuccessfully() {
            // Given
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            // Single-factor login path issues JWT with amr=["pwd"] via the two-arg variant.
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd"))).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(eq(existingUser), eq("192.168.1.1"), eq("Mozilla/5.0")))
                .thenReturn(refreshToken);

            // When
            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            assertThat(response.getRefreshToken()).isEqualTo("refresh-token-value");
            assertThat(response.getUser()).isNotNull();
            assertThat(response.getUser().getEmail()).isEqualTo("test@example.com");
            assertThat(response.getUser().getFirstName()).isEqualTo("John");
            assertThat(response.getUser().getLastName()).isEqualTo("Doe");

            verify(userRepository).findByEmail("test@example.com");
            verify(passwordEncoder).matches("Password123!", VALID_BCRYPT_HASH);
            verify(tokenGenerator).generateAccessToken("test@example.com", List.of("pwd"));
            verify(refreshTokenService).createRefreshToken(existingUser, "192.168.1.1", "Mozilla/5.0");
        }

        @Test
        @DisplayName("Should return correct user response fields")
        void shouldReturnCorrectUserResponseFields() {
            // Given
            User userWithFullDetails = User.builder()
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
                                  .enrolledAt(Instant.now().minus(Duration.ofDays(10)))                  .lastVerifiedAt(Instant.now().minus(Duration.ofDays(1)))
                                  .createdAt(Instant.now().minus(Duration.ofDays(30)))                .updatedAt(Instant.now())
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(userWithFullDetails));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            // Single-factor login path issues JWT with amr=["pwd"] via the two-arg variant.
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd"))).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            // When
            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            // Then
            assertThat(response.getUser().getPhoneNumber()).isEqualTo("+1234567890");
            assertThat(response.getUser().getAddress()).isEqualTo("123 Main St");
            assertThat(response.getUser().isBiometricEnrolled()).isTrue();
            assertThat(response.getUser().getVerificationCount()).isEqualTo(5);
        }
    }

    @Nested
    @DisplayName("Authentication Failures")
    class AuthenticationFailures {

        @Test
        @DisplayName("Should throw InvalidCredentialsException when user not found")
        void shouldThrowInvalidCredentialsExceptionWhenUserNotFound() {
            // Given
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                .isInstanceOf(InvalidCredentialsException.class);

            verify(userRepository).findByEmail("test@example.com");
            verify(passwordEncoder, never()).matches(any(), any());
            verify(tokenGenerator, never()).generateAccessToken(any());
        }

        @Test
        @DisplayName("Should throw InvalidCredentialsException when password does not match")
        void shouldThrowInvalidCredentialsExceptionWhenPasswordDoesNotMatch() {
            // Given
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(false);

            // When/Then
            assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                .isInstanceOf(InvalidCredentialsException.class);

            verify(userRepository).findByEmail("test@example.com");
            verify(passwordEncoder).matches("Password123!", VALID_BCRYPT_HASH);
            verify(tokenGenerator, never()).generateAccessToken(any());
            verify(refreshTokenService, never()).createRefreshToken(any(), any(), any());
        }

        @Test
        @DisplayName("Should throw same exception for both user not found and wrong password")
        void shouldThrowSameExceptionForSecurityReasons() {
            // Given - User not found
            when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

            AuthenticateUserCommand notFoundCommand = AuthenticateUserCommand.builder()
                .email("nonexistent@example.com")
                .password("anyPassword")
                .build();

            // When/Then - Should throw InvalidCredentialsException
            assertThatThrownBy(() -> authenticateUserService.execute(notFoundCommand))
                .isInstanceOf(InvalidCredentialsException.class);

            // Given - Wrong password
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
            when(passwordEncoder.matches("wrongPassword", VALID_BCRYPT_HASH)).thenReturn(false);

            AuthenticateUserCommand wrongPasswordCommand = AuthenticateUserCommand.builder()
                .email("test@example.com")
                .password("wrongPassword")
                .build();

            // When/Then - Should also throw InvalidCredentialsException (same type)
            assertThatThrownBy(() -> authenticateUserService.execute(wrongPasswordCommand))
                .isInstanceOf(InvalidCredentialsException.class);
        }
    }

    @Nested
    @DisplayName("Account Lockout (P0-#5)")
    class AccountLockout {

        @Test
        @DisplayName("Should throw AccountLockedException with remaining seconds when account is locked")
        void shouldThrowAccountLockedExceptionWhenAccountIsLocked() {
            // Given — user is locked with ~600 seconds remaining
            Instant lockedUntil = Instant.now().plusSeconds(600);
            User lockedUser = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .isLocked(true)
                .lockedUntil(lockedUntil)
                .failedLoginAttempts(5)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(lockedUser));

            // When/Then
            assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                .isInstanceOf(AccountLockedException.class)
                .satisfies(ex -> {
                    AccountLockedException ale = (AccountLockedException) ex;
                    assertThat(ale.getRemainingLockTimeSeconds())
                        .isBetween(595L, 600L);
                    assertThat(ale.getErrorCode()).isEqualTo("ACCOUNT_LOCKED");
                });

            // Password should never be checked when account is locked
            verify(passwordEncoder, never()).matches(any(), any());
            verify(tokenGenerator, never()).generateAccessToken(any(), any());
        }

        @Test
        @DisplayName("Should throw AccountLockedException on the 5th wrong-password attempt")
        void shouldThrowAccountLockedOnFifthFailure() {
            // Given — user already at 4 failed attempts, this is the 5th
            User userOnVerge = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .isLocked(false)
                .failedLoginAttempts(4)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(userOnVerge));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(false);

            // When/Then — must surface AccountLockedException, NOT InvalidCredentialsException
            assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                .isInstanceOf(AccountLockedException.class)
                .satisfies(ex -> {
                    AccountLockedException ale = (AccountLockedException) ex;
                    // 15-min lockout duration → ~900s remaining
                    assertThat(ale.getRemainingLockTimeSeconds())
                        .isBetween(890L, 900L);
                });

            verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("Should auto-unlock and proceed when lockedUntil has passed")
        void shouldAutoUnlockWhenLockedUntilExpired() {
            // Given — user was locked, but lockedUntil is in the past
            User expiredLockUser = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .isLocked(true)
                .lockedUntil(Instant.now().minusSeconds(1))
                .failedLoginAttempts(5)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(expiredLockUser));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd"))).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            // When — should succeed (auto-unlock path)
            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle null IP address and user agent")
        void shouldHandleNullIpAddressAndUserAgent() {
            // Given
            AuthenticateUserCommand commandWithNulls = AuthenticateUserCommand.builder()
                .email("test@example.com")
                .password("Password123!")
                .ipAddress(null)
                .userAgent(null)
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(existingUser));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            // Single-factor login path issues JWT with amr=["pwd"] via the two-arg variant.
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd"))).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(eq(existingUser), isNull(), isNull()))
                .thenReturn(refreshToken);

            // When
            AuthenticationResponse response = authenticateUserService.execute(commandWithNulls);

            // Then
            assertThat(response).isNotNull();
            verify(refreshTokenService).createRefreshToken(existingUser, null, null);
        }

        @Test
        @DisplayName("Should authenticate user with different status")
        void shouldAuthenticateUserWithDifferentStatus() {
            // Given
            User inactiveUser = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.INACTIVE)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(inactiveUser));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            // Single-factor login path issues JWT with amr=["pwd"] via the two-arg variant.
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd"))).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            // When
            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            // Then
            assertThat(response.getUser().getStatus()).isEqualTo("INACTIVE");
        }
    }
}
