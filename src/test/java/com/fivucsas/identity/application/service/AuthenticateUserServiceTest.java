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
import com.fivucsas.identity.domain.exception.TenantMismatchException;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.Tenant;
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
    @DisplayName("Tenant Mismatch (T-TENANT-GATE 2026-05-07)")
    class TenantMismatch {

        @Test
        @DisplayName("Should throw TenantMismatchException with required tenant name when user tenant != client tenant")
        void shouldThrowTenantMismatchWhenUserTenantDiffersFromClientTenant() {
            // Given — user belongs to Fivucsas system tenant, but the OAuth
            // client (Marmara hosted login) is bound to Marmara University.
            UUID userTenantId = UUID.randomUUID();
            UUID marmaraTenantId = UUID.randomUUID();

            Tenant userTenant = Tenant.builder().id(userTenantId).name("Fivucsas").build();
            Tenant marmaraTenant = Tenant.builder().id(marmaraTenantId).name("Marmara University").build();

            User gmailUser = User.builder()
                    .id(UUID.randomUUID())
                    .email("alice@gmail.com")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("Alice")
                    .lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .tenant(userTenant)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();

            OAuth2Client marmaraClient = OAuth2Client.builder()
                    .clientId("marmara-bys-demo")
                    .clientName("Marmara BYS")
                    .tenant(marmaraTenant)
                    .build();

            AuthenticateUserCommand command = AuthenticateUserCommand.builder()
                    .email("alice@gmail.com")
                    .password("Password123!")
                    .ipAddress("10.0.0.1")
                    .userAgent("ua")
                    .clientId("marmara-bys-demo")
                    .build();

            when(userRepository.findByEmail("alice@gmail.com")).thenReturn(Optional.of(gmailUser));
            when(oAuth2ClientRepository.findByClientId("marmara-bys-demo"))
                    .thenReturn(Optional.of(marmaraClient));

            // When/Then — must surface TenantMismatchException with the
            // tenant display name; password must NEVER be checked.
            assertThatThrownBy(() -> authenticateUserService.execute(command))
                    .isInstanceOf(TenantMismatchException.class)
                    .satisfies(ex -> {
                        TenantMismatchException tme = (TenantMismatchException) ex;
                        assertThat(tme.getRequiredTenant()).isEqualTo("Marmara University");
                        assertThat(tme.getErrorCode()).isEqualTo("TENANT_MISMATCH");
                    });

            // Critical: password must NOT be checked, MFA session must NOT be
            // created, and no token must be issued.
            verify(passwordEncoder, never()).matches(any(), any());
            verify(tokenGenerator, never()).generateAccessToken(any());
            verify(tokenGenerator, never()).generateAccessToken(any(), any());
            verify(refreshTokenService, never()).createRefreshToken(any(), any(), any());
        }

        @Test
        @DisplayName("Should NOT throw when user tenant matches client tenant")
        void shouldAllowLoginWhenUserAndClientShareTenant() {
            // Given — user and client both belong to Marmara
            UUID marmaraTenantId = UUID.randomUUID();
            Tenant marmaraTenant = Tenant.builder().id(marmaraTenantId).name("Marmara University").build();

            User marmaraUser = User.builder()
                    .id(UUID.randomUUID())
                    .email("staff@marmara.edu.tr")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("Staff")
                    .lastName("Member")
                    .status(UserStatus.ACTIVE)
                    .tenant(marmaraTenant)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();

            OAuth2Client marmaraClient = OAuth2Client.builder()
                    .clientId("marmara-bys-demo")
                    .clientName("Marmara BYS")
                    .tenant(marmaraTenant)
                    .build();

            AuthenticateUserCommand command = AuthenticateUserCommand.builder()
                    .email("staff@marmara.edu.tr")
                    .password("Password123!")
                    .ipAddress("10.0.0.1")
                    .userAgent("ua")
                    .clientId("marmara-bys-demo")
                    .build();

            when(userRepository.findByEmail("staff@marmara.edu.tr"))
                    .thenReturn(Optional.of(marmaraUser));
            when(oAuth2ClientRepository.findByClientId("marmara-bys-demo"))
                    .thenReturn(Optional.of(marmaraClient));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            when(tokenGenerator.generateAccessToken("staff@marmara.edu.tr", List.of("pwd")))
                    .thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            // When
            AuthenticationResponse response = authenticateUserService.execute(command);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
        }

        @Test
        @DisplayName("Should skip tenant check when clientId is blank (no OAuth flow)")
        void shouldSkipTenantCheckWhenClientIdBlank() {
            // Given — vanilla password login from the dashboard (no client_id)
            when(userRepository.findByEmail("test@example.com"))
                    .thenReturn(Optional.of(existingUser));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd")))
                    .thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            // When — validCommand has no clientId
            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            // Then — tenant lookup must never happen
            assertThat(response).isNotNull();
            verify(oAuth2ClientRepository, never()).findByClientId(any());
        }

        @Test
        @DisplayName("Should fall back to client name when tenant has no display name")
        void shouldFallBackToClientNameWhenTenantNameMissing() {
            // Given — pathological case: tenant exists but its name is empty.
            UUID userTenantId = UUID.randomUUID();
            UUID otherTenantId = UUID.randomUUID();

            Tenant userTenant = Tenant.builder().id(userTenantId).name("Fivucsas").build();
            Tenant nameMissing = Tenant.builder().id(otherTenantId).name("").build();

            User user = User.builder()
                    .id(UUID.randomUUID())
                    .email("alice@gmail.com")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("Alice")
                    .lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .tenant(userTenant)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();

            OAuth2Client client = OAuth2Client.builder()
                    .clientId("acme-portal")
                    .clientName("Acme Portal")
                    .tenant(nameMissing)
                    .build();

            AuthenticateUserCommand command = AuthenticateUserCommand.builder()
                    .email("alice@gmail.com")
                    .password("x")
                    .clientId("acme-portal")
                    .build();

            when(userRepository.findByEmail("alice@gmail.com")).thenReturn(Optional.of(user));
            when(oAuth2ClientRepository.findByClientId("acme-portal"))
                    .thenReturn(Optional.of(client));

            // Then
            assertThatThrownBy(() -> authenticateUserService.execute(command))
                    .isInstanceOf(TenantMismatchException.class)
                    .satisfies(ex -> assertThat(((TenantMismatchException) ex).getRequiredTenant())
                            .isEqualTo("Acme Portal"));
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
