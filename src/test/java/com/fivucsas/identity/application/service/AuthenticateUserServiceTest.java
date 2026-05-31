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
import com.fivucsas.identity.domain.exception.TenantSuspendedException;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
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

    @Mock
    private com.fivucsas.identity.application.service.ConfigDrivenLoginPolicy configDrivenLoginPolicy;

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

            // P0-#8 (2026-05-07): both tenants must be ACTIVE so the new
            // tenant-suspension gate doesn't short-circuit ahead of the
            // tenant-mismatch check this test is asserting.
            Tenant userTenant = Tenant.builder()
                    .id(userTenantId).name("Fivucsas").status(TenantStatus.ACTIVE).build();
            Tenant marmaraTenant = Tenant.builder()
                    .id(marmaraTenantId).name("Marmara University").status(TenantStatus.ACTIVE).build();

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
            // P0-#8 (2026-05-07): ACTIVE so the tenant-suspension gate is
            // a no-op here.
            Tenant marmaraTenant = Tenant.builder()
                    .id(marmaraTenantId).name("Marmara University").status(TenantStatus.ACTIVE).build();

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

            // P0-#8 (2026-05-07): ACTIVE so the tenant-suspension gate
            // does not preempt the tenant-mismatch surface under test.
            Tenant userTenant = Tenant.builder()
                    .id(userTenantId).name("Fivucsas").status(TenantStatus.ACTIVE).build();
            Tenant nameMissing = Tenant.builder()
                    .id(otherTenantId).name("").status(TenantStatus.ACTIVE).build();

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

    /**
     * Identifier-first pre-flight ({@code checkTenantEligibility}): surfaces the
     * tenant-mismatch on the EMAIL step (no password verified, no lockout touched).
     * Shares {@code enforceTenantLock} with the password path, so behavior matches
     * the gate above.
     */
    @Nested
    @DisplayName("Pre-flight tenant eligibility (identifier-first)")
    class PreflightTenantEligibility {

        @Test
        @DisplayName("Throws TenantMismatchException when email belongs to a different tenant — no password checked")
        void throwsOnMismatch() {
            Tenant userTenant = Tenant.builder()
                    .id(UUID.randomUUID()).name("Fivucsas").status(TenantStatus.ACTIVE).build();
            Tenant marmaraTenant = Tenant.builder()
                    .id(UUID.randomUUID()).name("Marmara University").status(TenantStatus.ACTIVE).build();
            User gmailUser = User.builder()
                    .id(UUID.randomUUID()).email("alice@gmail.com").passwordHash(VALID_BCRYPT_HASH)
                    .firstName("Alice").lastName("Doe").status(UserStatus.ACTIVE).tenant(userTenant)
                    .createdAt(Instant.now()).updatedAt(Instant.now()).build();
            OAuth2Client marmaraClient = OAuth2Client.builder()
                    .clientId("marmara-bys-demo").clientName("Marmara BYS").tenant(marmaraTenant).build();

            when(userRepository.findByEmail("alice@gmail.com")).thenReturn(Optional.of(gmailUser));
            when(oAuth2ClientRepository.findByClientId("marmara-bys-demo"))
                    .thenReturn(Optional.of(marmaraClient));

            assertThatThrownBy(() ->
                    authenticateUserService.checkTenantEligibility("alice@gmail.com", "marmara-bys-demo"))
                    .isInstanceOf(TenantMismatchException.class)
                    .satisfies(ex -> assertThat(((TenantMismatchException) ex).getRequiredTenant())
                            .isEqualTo("Marmara University"));

            // No password is ever checked on the pre-flight.
            verify(passwordEncoder, never()).matches(any(), any());
        }

        @Test
        @DisplayName("No throw when the email belongs to the client's tenant")
        void allowsSameTenant() {
            Tenant marmaraTenant = Tenant.builder()
                    .id(UUID.randomUUID()).name("Marmara University").status(TenantStatus.ACTIVE).build();
            User marmaraUser = User.builder()
                    .id(UUID.randomUUID()).email("staff@marmara.edu.tr").passwordHash(VALID_BCRYPT_HASH)
                    .firstName("Staff").lastName("Member").status(UserStatus.ACTIVE).tenant(marmaraTenant)
                    .createdAt(Instant.now()).updatedAt(Instant.now()).build();
            OAuth2Client marmaraClient = OAuth2Client.builder()
                    .clientId("marmara-bys-demo").clientName("Marmara BYS").tenant(marmaraTenant).build();

            when(userRepository.findByEmail("staff@marmara.edu.tr")).thenReturn(Optional.of(marmaraUser));
            when(oAuth2ClientRepository.findByClientId("marmara-bys-demo"))
                    .thenReturn(Optional.of(marmaraClient));

            authenticateUserService.checkTenantEligibility("staff@marmara.edu.tr", "marmara-bys-demo");
            // no exception
        }

        @Test
        @DisplayName("Unknown email is a silent no-op (no enumeration beyond the password-step gate)")
        void unknownEmailNoOp() {
            when(userRepository.findByEmail("ghost@nowhere.test")).thenReturn(Optional.empty());

            authenticateUserService.checkTenantEligibility("ghost@nowhere.test", "marmara-bys-demo");

            verify(oAuth2ClientRepository, never()).findByClientId(any());
        }

        @Test
        @DisplayName("Blank clientId skips the tenant lookup entirely")
        void blankClientIdNoLookup() {
            User marmaraUser = User.builder()
                    .id(UUID.randomUUID()).email("staff@marmara.edu.tr").passwordHash(VALID_BCRYPT_HASH)
                    .firstName("Staff").lastName("Member").status(UserStatus.ACTIVE)
                    .tenant(Tenant.builder().id(UUID.randomUUID()).name("Marmara University")
                            .status(TenantStatus.ACTIVE).build())
                    .createdAt(Instant.now()).updatedAt(Instant.now()).build();
            when(userRepository.findByEmail("staff@marmara.edu.tr")).thenReturn(Optional.of(marmaraUser));

            authenticateUserService.checkTenantEligibility("staff@marmara.edu.tr", "");

            verify(oAuth2ClientRepository, never()).findByClientId(any());
        }
    }

    /**
     * P0-#8 (INVESTIGATION_MASTER_2026-05-07): tenant suspension gate.
     *
     * <p>Asserts that authentication fails with HTTP 423
     * {@link TenantSuspendedException} when the user's tenant is in any
     * non-ACTIVE status (SUSPENDED, INACTIVE, PENDING). Critically, the
     * password must NEVER be checked and no token must be issued — the
     * suspension takes precedence over every other branch.</p>
     */
    @Nested
    @DisplayName("Tenant Suspension (P0-#8)")
    class TenantSuspended {

        @Test
        @DisplayName("Should throw TenantSuspendedException when user.tenant.status = SUSPENDED")
        void shouldThrowWhenTenantSuspended() {
            // Given — user belongs to a tenant that has been suspended.
            Tenant suspendedTenant = Tenant.builder()
                    .id(UUID.randomUUID())
                    .name("Suspended Tenant")
                    .status(TenantStatus.SUSPENDED)
                    .build();
            User suspendedTenantUser = User.builder()
                    .id(UUID.randomUUID())
                    .email("test@example.com")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("John")
                    .lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .tenant(suspendedTenant)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();

            when(userRepository.findByEmail("test@example.com"))
                    .thenReturn(Optional.of(suspendedTenantUser));

            // When/Then
            assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                    .isInstanceOf(TenantSuspendedException.class)
                    .satisfies(ex -> {
                        TenantSuspendedException tse = (TenantSuspendedException) ex;
                        assertThat(tse.getStatus()).isEqualTo(TenantStatus.SUSPENDED);
                        assertThat(tse.getErrorCode()).isEqualTo("TENANT_SUSPENDED");
                    });

            // Critical: password must NOT be checked, no token issued.
            verify(passwordEncoder, never()).matches(any(), any());
            verify(tokenGenerator, never()).generateAccessToken(any());
            verify(tokenGenerator, never()).generateAccessToken(any(), any());
            verify(refreshTokenService, never()).createRefreshToken(any(), any(), any());
        }

        @Test
        @DisplayName("Should also throw for INACTIVE and PENDING tenants")
        void shouldThrowForInactiveAndPending() {
            for (TenantStatus blockedStatus : List.of(TenantStatus.INACTIVE, TenantStatus.PENDING)) {
                Tenant blockedTenant = Tenant.builder()
                        .id(UUID.randomUUID())
                        .name(blockedStatus + " Tenant")
                        .status(blockedStatus)
                        .build();
                User blockedUser = User.builder()
                        .id(UUID.randomUUID())
                        .email("test@example.com")
                        .passwordHash(VALID_BCRYPT_HASH)
                        .firstName("John")
                        .lastName("Doe")
                        .status(UserStatus.ACTIVE)
                        .tenant(blockedTenant)
                        .createdAt(Instant.now())
                        .updatedAt(Instant.now())
                        .build();

                when(userRepository.findByEmail("test@example.com"))
                        .thenReturn(Optional.of(blockedUser));

                assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                        .isInstanceOf(TenantSuspendedException.class)
                        .satisfies(ex -> assertThat(((TenantSuspendedException) ex).getStatus())
                                .isEqualTo(blockedStatus));

                reset(userRepository);
            }
        }

        @Test
        @DisplayName("Should NOT throw when user.tenant.status = ACTIVE")
        void shouldAllowActiveTenant() {
            // Given — ACTIVE tenant, password matches, no MFA configured.
            Tenant activeTenant = Tenant.builder()
                    .id(UUID.randomUUID())
                    .name("Active Tenant")
                    .status(TenantStatus.ACTIVE)
                    .build();
            User activeUser = User.builder()
                    .id(UUID.randomUUID())
                    .email("test@example.com")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("John")
                    .lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .tenant(activeTenant)
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(activeUser));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd"))).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            // When
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

    @Nested
    @DisplayName("Config-driven Layer-1 (task #16 B)")
    class ConfigDrivenLayer1 {

        private com.fivucsas.identity.entity.AuthMethod method(
                com.fivucsas.identity.domain.model.auth.AuthMethodType type, boolean requiresEnrollment) {
            return com.fivucsas.identity.entity.AuthMethod.builder()
                    .id(UUID.randomUUID())
                    .type(type)
                    .name(type.name())
                    .category(com.fivucsas.identity.domain.model.auth.AuthMethodCategory.BASIC)
                    .platforms(List.of("WEB"))
                    .requiresEnrollment(requiresEnrollment)
                    .build();
        }

        private com.fivucsas.identity.entity.AuthFlowStep step(
                int order, com.fivucsas.identity.entity.AuthMethod m) {
            return com.fivucsas.identity.entity.AuthFlowStep.builder()
                    .id(UUID.randomUUID())
                    .stepOrder(order)
                    .authMethod(m)
                    .isRequired(true)
                    .build();
        }

        private com.fivucsas.identity.entity.AuthFlow flow(
                UUID tenantId, com.fivucsas.identity.entity.AuthFlowStep... steps) {
            Tenant tenant = Tenant.builder().id(tenantId).name("Acme").status(TenantStatus.ACTIVE).build();
            return com.fivucsas.identity.entity.AuthFlow.builder()
                    .id(UUID.randomUUID())
                    .tenant(tenant)
                    .name("Login")
                    .operationType(com.fivucsas.identity.domain.model.auth.OperationType.APP_LOGIN)
                    .isDefault(true)
                    .isActive(true)
                    .steps(new java.util.ArrayList<>(List.of(steps)))
                    .build();
        }

        private User tenantUser(UUID tenantId) {
            Tenant tenant = Tenant.builder().id(tenantId).name("Acme").status(TenantStatus.ACTIVE).build();
            return User.builder()
                    .id(UUID.randomUUID())
                    .email("test@example.com")
                    .passwordHash(VALID_BCRYPT_HASH)
                    .firstName("John").lastName("Doe")
                    .status(UserStatus.ACTIVE)
                    .tenant(tenant)
                    .createdAt(Instant.now()).updatedAt(Instant.now())
                    .build();
        }

        @Test
        @DisplayName("Layer-1=EMAIL_OTP: no password check; MFA pending at step 1 with no completed methods")
        void passwordlessLayer1StartsAtStepOne() {
            UUID tenantId = UUID.randomUUID();
            User user = tenantUser(tenantId);
            var emailOtp = method(com.fivucsas.identity.domain.model.auth.AuthMethodType.EMAIL_OTP, false);
            var loginFlow = flow(tenantId, step(1, emailOtp));

            when(configDrivenLoginPolicy.isEnabledFor(tenantId)).thenReturn(true); // engine ON
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
            when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    eq(tenantId), eq(com.fivucsas.identity.domain.model.auth.OperationType.APP_LOGIN)))
                    .thenReturn(Optional.of(loginFlow));
            when(enrollmentHealthService.validateEnrollments(user.getId()))
                    .thenReturn(java.util.Map.of());

            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            // No tokens; MFA pending at step 1; password was NEVER verified.
            assertThat(response.isMfaRequired()).isTrue();
            assertThat(response.getAccessToken()).isNull();
            assertThat(response.getCurrentStep()).isEqualTo(1);
            assertThat(response.getCompletedMethods()).isEmpty();
            verify(passwordEncoder, never()).matches(any(), any());
            verify(mfaSessionRepository).save(any());
        }

        @Test
        @DisplayName("Layer-1=PASSWORD with a 2nd step: legacy behavior — password verified, MFA pending at step 2 with PASSWORD completed")
        void passwordLayer1IsUnchanged() {
            UUID tenantId = UUID.randomUUID();
            User user = tenantUser(tenantId);
            var password = method(com.fivucsas.identity.domain.model.auth.AuthMethodType.PASSWORD, true);
            var emailOtp = method(com.fivucsas.identity.domain.model.auth.AuthMethodType.EMAIL_OTP, false);
            var loginFlow = flow(tenantId, step(1, password), step(2, emailOtp));

            when(configDrivenLoginPolicy.isEnabledFor(tenantId)).thenReturn(true); // engine ON
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    eq(tenantId), eq(com.fivucsas.identity.domain.model.auth.OperationType.APP_LOGIN)))
                    .thenReturn(Optional.of(loginFlow));
            when(enrollmentHealthService.validateEnrollments(user.getId()))
                    .thenReturn(java.util.Map.of());

            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            assertThat(response.isMfaRequired()).isTrue();
            assertThat(response.getAccessToken()).isNull();
            assertThat(response.getCurrentStep()).isEqualTo(2);
            assertThat(response.getCompletedMethods()).containsExactly("PASSWORD");
            verify(passwordEncoder).matches("Password123!", VALID_BCRYPT_HASH);
        }

        @Test
        @DisplayName("Layer-1=PASSWORD single step: unchanged single-factor token mint (amr=pwd)")
        void passwordLayer1SingleStepMints() {
            UUID tenantId = UUID.randomUUID();
            User user = tenantUser(tenantId);
            var password = method(com.fivucsas.identity.domain.model.auth.AuthMethodType.PASSWORD, true);
            var loginFlow = flow(tenantId, step(1, password));

            when(configDrivenLoginPolicy.isEnabledFor(tenantId)).thenReturn(true); // engine ON
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    eq(tenantId), eq(com.fivucsas.identity.domain.model.auth.OperationType.APP_LOGIN)))
                    .thenReturn(Optional.of(loginFlow));
            when(enrollmentHealthService.validateEnrollments(user.getId()))
                    .thenReturn(java.util.Map.of());
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd")))
                    .thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(eq(user), any(), any())).thenReturn(refreshToken);

            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            assertThat(response.isMfaRequired()).isFalse();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            verify(tokenGenerator).generateAccessToken("test@example.com", List.of("pwd"));
        }

        @Test
        @DisplayName("REVERSIBILITY: flag OFF ⇒ even an EMAIL_OTP-Layer-1 flow runs the LEGACY hard password gate")
        void flagOffForcesLegacyPasswordGate() {
            UUID tenantId = UUID.randomUUID();
            User user = tenantUser(tenantId);
            // Tenant configured EMAIL_OTP as Layer-1, but the engine is OFF for it.
            var emailOtp = method(com.fivucsas.identity.domain.model.auth.AuthMethodType.EMAIL_OTP, false);
            var loginFlow = flow(tenantId, step(1, emailOtp));

            when(configDrivenLoginPolicy.isEnabledFor(tenantId)).thenReturn(false); // engine OFF
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
            // Legacy path MUST verify the password (wrong password → InvalidCredentials,
            // proving the hard gate still runs despite the EMAIL_OTP Layer-1 config).
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(false);

            assertThatThrownBy(() -> authenticateUserService.execute(validCommand))
                    .isInstanceOf(InvalidCredentialsException.class);

            verify(passwordEncoder).matches("Password123!", VALID_BCRYPT_HASH);
            // No MFA session opened — flag OFF never reaches the config-driven branch.
            verify(mfaSessionRepository, never()).save(any());
        }

        @Test
        @DisplayName("REVERSIBILITY: flag OFF ⇒ correct password mints directly (amr=pwd), no flow lookup drives Layer-1")
        void flagOffCorrectPasswordMintsLegacy() {
            UUID tenantId = UUID.randomUUID();
            User user = tenantUser(tenantId);
            var emailOtp = method(com.fivucsas.identity.domain.model.auth.AuthMethodType.EMAIL_OTP, false);
            // A default flow exists with a 2nd step, but flag OFF means the legacy
            // path treats step 1 as PASSWORD and only looks for steps beyond step 1.
            // Here the only step is EMAIL_OTP at order 1, so legacy sees NO remaining
            // steps (order>1) → single-factor mint.
            var loginFlow = flow(tenantId, step(1, emailOtp));

            when(configDrivenLoginPolicy.isEnabledFor(tenantId)).thenReturn(false); // engine OFF
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
            when(passwordEncoder.matches("Password123!", VALID_BCRYPT_HASH)).thenReturn(true);
            when(authFlowRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(
                    eq(tenantId), eq(com.fivucsas.identity.domain.model.auth.OperationType.APP_LOGIN)))
                    .thenReturn(Optional.of(loginFlow));
            when(enrollmentHealthService.validateEnrollments(user.getId()))
                    .thenReturn(java.util.Map.of());
            when(tokenGenerator.generateAccessToken("test@example.com", List.of("pwd")))
                    .thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(eq(user), any(), any())).thenReturn(refreshToken);

            AuthenticationResponse response = authenticateUserService.execute(validCommand);

            assertThat(response.isMfaRequired()).isFalse();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            verify(passwordEncoder).matches("Password123!", VALID_BCRYPT_HASH);
            verify(mfaSessionRepository, never()).save(any());
        }
    }
}
