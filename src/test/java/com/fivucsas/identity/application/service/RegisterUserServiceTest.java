package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.EventPublisherPort;
import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.InvalidEmailException;
import com.fivucsas.identity.domain.exception.TenantUserQuotaExceededException;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantEmailDomain;
import com.fivucsas.identity.entity.TenantStatus;
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
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
@DisplayName("RegisterUserService Tests")
class RegisterUserServiceTest {

    // Valid BCrypt hash for testing (represents "Password123!")
    private static final String VALID_BCRYPT_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Mock
    private UserRepository userRepository;

    @Mock
    private JpaTenantRepository tenantRepository;

    @Mock
    private TenantEmailDomainRepository tenantEmailDomainRepository;

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
    private OtpService otpService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private RegisterUserService registerUserService;

    private RegisterUserCommand validCommand;
    private User savedUser;
    private RefreshToken refreshToken;
    private Tenant testTenant;

    @BeforeEach
    void setUp() {
        testTenant = Tenant.builder()
            .id(UUID.randomUUID())
            .name("Test Tenant")
            .slug("test-tenant")
            .contactEmail("admin@test.com")
            .status(TenantStatus.ACTIVE)
            .build();

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
            .passwordHash(VALID_BCRYPT_HASH)
            .firstName("John")
            .lastName("Doe")
            .tenant(testTenant)
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

        // Configure tenant repository mock to return test tenant
        lenient().when(tenantRepository.findBySlug("test-tenant")).thenReturn(Optional.of(testTenant));
        lenient().when(tenantRepository.findAll()).thenReturn(List.of(testTenant));
        // P0-#7: tenant user-quota count defaults to 0 (well below max_users
        // = 100) for the existing happy-path tests. The dedicated quota
        // exceedance test below overrides this stub explicitly.
        lenient().when(userRepository.countByTenantId(any())).thenReturn(0L);
    }

    @Nested
    @DisplayName("Successful Registration")
    class SuccessfulRegistration {

        @Test
        @DisplayName("Should register user successfully with valid command")
        void shouldRegisterUserSuccessfully() {
            // Given
            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn(VALID_BCRYPT_HASH);
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
            when(passwordEncoder.encode("Password123!")).thenReturn(VALID_BCRYPT_HASH);
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
            assertThat(capturedUser.getPasswordHash()).isEqualTo(VALID_BCRYPT_HASH);
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
        @DisplayName("Should throw IllegalArgumentException for invalid email format")
        void shouldThrowIllegalArgumentExceptionForInvalidEmail() {
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
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid email format");

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
            when(passwordEncoder.encode("Password123!")).thenReturn(VALID_BCRYPT_HASH);
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
                .passwordHash(VALID_BCRYPT_HASH)
                .firstName("José-María")
                .lastName("O'Connor")
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn(VALID_BCRYPT_HASH);
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

    /**
     * P0-#7 (INVESTIGATION_MASTER_2026-05-07): tenant.max_users enforcement.
     *
     * <p>Asserts that registration fails with HTTP 409
     * {@link TenantUserQuotaExceededException} when the tenant has already
     * reached its configured user-quota ceiling, AND that the user is never
     * persisted nor a token issued in that case.</p>
     */
    @Nested
    @DisplayName("Tenant user-quota enforcement (P0-#7)")
    class TenantUserQuotaEnforcement {

        @Test
        @DisplayName("Should throw TenantUserQuotaExceededException when count >= maxUsers")
        void shouldThrowWhenQuotaExhausted() {
            // Given — tenant has maxUsers=5 and is already at 5 users
            Tenant cappedTenant = Tenant.builder()
                .id(UUID.randomUUID())
                .name("Capped Tenant")
                .slug("capped-tenant")
                .contactEmail("admin@capped.com")
                .status(TenantStatus.ACTIVE)
                .maxUsers(5)
                .build();
            lenient().when(tenantRepository.findBySlug("capped-tenant"))
                .thenReturn(Optional.of(cappedTenant));
            lenient().when(tenantRepository.findAll()).thenReturn(List.of(cappedTenant));
            // Override the default-zero stub for THIS tenant's id only.
            when(userRepository.countByTenantId(cappedTenant.getId())).thenReturn(5L);
            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

            // Wire RegisterUserService to land on this tenant: no V44
            // mapping, no legacy mapping → falls back to default slug, which
            // we now point at cappedTenant.
            ReflectionTestUtils.setField(registerUserService, "defaultTenantSlug", "capped-tenant");
            when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("example.com"))
                .thenReturn(Optional.empty());
            when(tenantRepository.findByLegacyDomainIgnoreCase("example.com"))
                .thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> registerUserService.execute(validCommand))
                .isInstanceOf(TenantUserQuotaExceededException.class)
                .satisfies(ex -> {
                    TenantUserQuotaExceededException tqe =
                        (TenantUserQuotaExceededException) ex;
                    assertThat(tqe.getMaxUsers()).isEqualTo(5);
                    assertThat(tqe.getErrorCode()).isEqualTo("TENANT_USER_QUOTA_EXCEEDED");
                });

            // Critical: count must have been queried; user must NOT be saved;
            // no token issued.
            verify(userRepository).countByTenantId(cappedTenant.getId());
            verify(userRepository, never()).save(any(User.class));
            verify(tokenGenerator, never()).generateAccessToken(any());
            verify(refreshTokenService, never()).createRefreshToken(any(), any(), any());
        }

        @Test
        @DisplayName("Should allow registration when count is one below maxUsers")
        void shouldAllowWhenJustBelowQuota() {
            // Given — maxUsers=5, currently 4 users → registration should succeed.
            Tenant nearCapTenant = Tenant.builder()
                .id(UUID.randomUUID())
                .name("Near Cap Tenant")
                .slug("near-cap-tenant")
                .contactEmail("admin@nearcap.com")
                .status(TenantStatus.ACTIVE)
                .maxUsers(5)
                .build();
            lenient().when(tenantRepository.findBySlug("near-cap-tenant"))
                .thenReturn(Optional.of(nearCapTenant));
            when(userRepository.countByTenantId(nearCapTenant.getId())).thenReturn(4L);
            when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
            when(passwordEncoder.encode("Password123!")).thenReturn(VALID_BCRYPT_HASH);
            when(userRepository.save(any(User.class))).thenReturn(savedUser);
            when(tokenGenerator.generateAccessToken("test@example.com")).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);

            ReflectionTestUtils.setField(registerUserService, "defaultTenantSlug", "near-cap-tenant");
            when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("example.com"))
                .thenReturn(Optional.empty());
            when(tenantRepository.findByLegacyDomainIgnoreCase("example.com"))
                .thenReturn(Optional.empty());

            // When
            AuthenticationResponse response = registerUserService.execute(validCommand);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo("access-token");
            verify(userRepository).save(any(User.class));
        }
    }

    /**
     * Wire-up tests for V44 {@code tenant_email_domains}.
     *
     * <p>Asserts that on registration the user's tenant is resolved by the
     * email-domain lookup table when present, falls back to the legacy
     * {@code tenants.domain} column when the new table has no row, and
     * finally falls back to the default tenant when neither path matches.</p>
     */
    @Nested
    @DisplayName("Tenant resolution by email domain (V44 wire-up)")
    class TenantResolutionByEmailDomain {

        private static final UUID MARMARA_TENANT_ID =
            UUID.fromString("11111111-1111-1111-1111-111111111111");

        private Tenant marmaraTenant;

        @BeforeEach
        void setUpMarmaraTenant() {
            marmaraTenant = Tenant.builder()
                .id(MARMARA_TENANT_ID)
                .name("Marmara University")
                .slug("marmara")
                .contactEmail("admin@marmara.edu.tr")
                .status(TenantStatus.ACTIVE)
                .build();
        }

        private RegisterUserCommand registrationFor(String emailAddress) {
            return RegisterUserCommand.builder()
                .email(emailAddress)
                .password("Password123!")
                .firstName("Ada")
                .lastName("Lovelace")
                .ipAddress("10.0.0.1")
                .userAgent("JUnit")
                .build();
        }

        private void stubCommonRegistrationCollaborators(String emailAddress) {
            when(userRepository.existsByEmail(emailAddress)).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn(VALID_BCRYPT_HASH);
            // Ensure the persisted User has an ID — RegisterUserService.execute()
            // immediately calls savedUser.getId().toString() for audit logging.
            when(userRepository.save(any(User.class))).thenAnswer(inv -> {
                User input = inv.getArgument(0);
                return User.builder()
                    .id(UUID.randomUUID())
                    .email(input.getEmail())
                    .passwordHash(input.getPasswordHash())
                    .firstName(input.getFirstName())
                    .lastName(input.getLastName())
                    .tenant(input.getTenant())
                    .status(input.getStatus())
                    .isBiometricEnrolled(input.isBiometricEnrolled())
                    .verificationCount(input.getVerificationCount())
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build();
            });
            when(tokenGenerator.generateAccessToken(emailAddress)).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any(), any())).thenReturn(refreshToken);
        }

        @Test
        @DisplayName("marun.edu.tr resolves to Marmara tenant via tenant_email_domains")
        void marunResolvesToMarmaraTenant() {
            // Given — V44 backfill seeds (Marmara, marun.edu.tr, is_primary=false)
            String emailAddress = "ahmet@marun.edu.tr";
            TenantEmailDomain marunRow = TenantEmailDomain.create(MARMARA_TENANT_ID, "marun.edu.tr", false);
            when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("marun.edu.tr"))
                .thenReturn(Optional.of(marunRow));
            when(tenantRepository.findById(MARMARA_TENANT_ID)).thenReturn(Optional.of(marmaraTenant));
            stubCommonRegistrationCollaborators(emailAddress);

            // When
            registerUserService.execute(registrationFor(emailAddress));

            // Then — saved user is on the Marmara tenant
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getTenant().getId()).isEqualTo(MARMARA_TENANT_ID);

            // Legacy fall-back must NOT be consulted when new-table lookup hits.
            verify(tenantRepository, never()).findByLegacyDomainIgnoreCase(anyString());
            // Default-slug fall-back must NOT be used either.
            verify(tenantRepository, never()).findBySlug(anyString());
        }

        @Test
        @DisplayName("marmara.edu.tr resolves to the same Marmara tenant")
        void marmaraResolvesToSameTenant() {
            // Given — primary domain row backfilled by V44
            String emailAddress = "student@marmara.edu.tr";
            TenantEmailDomain primaryRow = TenantEmailDomain.create(MARMARA_TENANT_ID, "marmara.edu.tr", true);
            when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("marmara.edu.tr"))
                .thenReturn(Optional.of(primaryRow));
            when(tenantRepository.findById(MARMARA_TENANT_ID)).thenReturn(Optional.of(marmaraTenant));
            stubCommonRegistrationCollaborators(emailAddress);

            // When
            registerUserService.execute(registrationFor(emailAddress));

            // Then
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getTenant().getId()).isEqualTo(MARMARA_TENANT_ID);
            assertThat(userCaptor.getValue().getTenant().getSlug()).isEqualTo("marmara");
        }

        /**
         * V62 — opt-in email-domain enforcement.
         *
         * <p>When the resolved tenant has {@code enforce_domain_matching=true},
         * a registrant whose email domain is NOT in that tenant's
         * tenant_email_domains is rejected with
         * {@link com.fivucsas.identity.domain.exception.EmailDomainNotAllowedException};
         * an allowed domain still registers normally. Mirrors the marun/marmara
         * resolution tests above.</p>
         */
        @Nested
        @DisplayName("Email-domain enforcement (V62)")
        class EmailDomainEnforcement {

            private Tenant enforcingMarmara() {
                return Tenant.builder()
                    .id(MARMARA_TENANT_ID)
                    .name("Marmara University")
                    .slug("marmara")
                    .contactEmail("admin@marmara.edu.tr")
                    .status(TenantStatus.ACTIVE)
                    .maxUsers(100)
                    .enforceDomainMatching(true)
                    .build();
            }

            @Test
            @DisplayName("marun.edu.tr is allowed when enforcement is on (domain in registry)")
            void allowedDomainRegistersUnderEnforcement() {
                String emailAddress = "ahmet@marun.edu.tr";
                Tenant marmara = enforcingMarmara();
                TenantEmailDomain marunRow = TenantEmailDomain.create(MARMARA_TENANT_ID, "marun.edu.tr", false);

                when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("marun.edu.tr"))
                    .thenReturn(Optional.of(marunRow));
                when(tenantRepository.findById(MARMARA_TENANT_ID)).thenReturn(Optional.of(marmara));
                stubCommonRegistrationCollaborators(emailAddress);

                registerUserService.execute(registrationFor(emailAddress));

                ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
                verify(userRepository).save(userCaptor.capture());
                assertThat(userCaptor.getValue().getTenant().getId()).isEqualTo(MARMARA_TENANT_ID);
            }

            @Test
            @DisplayName("gmail.com is rejected when targeting an enforcing tenant via TenantContext")
            void disallowedDomainRejectedUnderEnforcement() {
                String emailAddress = "outsider@gmail.com";
                Tenant marmara = enforcingMarmara();

                // Target Marmara explicitly (invitation/multi-tenant header path)
                // so resolution lands on the enforcing tenant regardless of domain.
                com.fivucsas.identity.infrastructure.multitenancy.TenantContext.setCurrentTenant(MARMARA_TENANT_ID);
                try {
                    when(tenantRepository.findById(MARMARA_TENANT_ID)).thenReturn(Optional.of(marmara));
                    // gmail.com is not owned by any tenant.
                    when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("gmail.com"))
                        .thenReturn(Optional.empty());
                    when(userRepository.existsByEmail(emailAddress)).thenReturn(false);

                    assertThatThrownBy(() -> registerUserService.execute(registrationFor(emailAddress)))
                        .isInstanceOf(com.fivucsas.identity.domain.exception.EmailDomainNotAllowedException.class)
                        .satisfies(ex -> assertThat(
                            ((com.fivucsas.identity.domain.exception.EmailDomainNotAllowedException) ex)
                                .getEmailDomain()).isEqualTo("gmail.com"));

                    // Rejected before persistence / token issuance / bcrypt hash.
                    verify(userRepository, never()).save(any(User.class));
                    verify(tokenGenerator, never()).generateAccessToken(any());
                    verify(passwordEncoder, never()).encode(any());
                } finally {
                    com.fivucsas.identity.infrastructure.multitenancy.TenantContext.clear();
                }
            }

            @Test
            @DisplayName("A domain owned by ANOTHER tenant does not satisfy this tenant's gate")
            void domainOwnedByAnotherTenantRejected() {
                String emailAddress = "outsider@othertenant.edu";
                Tenant marmara = enforcingMarmara();
                UUID otherTenantId = UUID.randomUUID();
                // othertenant.edu is owned by a DIFFERENT tenant.
                TenantEmailDomain otherRow = TenantEmailDomain.create(otherTenantId, "othertenant.edu", false);

                com.fivucsas.identity.infrastructure.multitenancy.TenantContext.setCurrentTenant(MARMARA_TENANT_ID);
                try {
                    when(tenantRepository.findById(MARMARA_TENANT_ID)).thenReturn(Optional.of(marmara));
                    when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("othertenant.edu"))
                        .thenReturn(Optional.of(otherRow));
                    when(userRepository.existsByEmail(emailAddress)).thenReturn(false);

                    assertThatThrownBy(() -> registerUserService.execute(registrationFor(emailAddress)))
                        .isInstanceOf(com.fivucsas.identity.domain.exception.EmailDomainNotAllowedException.class);

                    verify(userRepository, never()).save(any(User.class));
                } finally {
                    com.fivucsas.identity.infrastructure.multitenancy.TenantContext.clear();
                }
            }
        }

        @Test
        @DisplayName("Unknown domain falls through legacy lookup, then to default tenant")
        void unknownDomainFallsThroughToDefault() {
            // Given — neither path returns a tenant
            String emailAddress = "stranger@unknown.edu.tr";
            when(tenantEmailDomainRepository.findByIdEmailDomainIgnoreCaseAndVerifiedTrue("unknown.edu.tr"))
                .thenReturn(Optional.empty());
            when(tenantRepository.findByLegacyDomainIgnoreCase("unknown.edu.tr"))
                .thenReturn(Optional.empty());
            // Default tenant fall-back (testTenant is wired up by parent setUp())
            stubCommonRegistrationCollaborators(emailAddress);

            // When
            registerUserService.execute(registrationFor(emailAddress));

            // Then — legacy was consulted (verifying the fall-through chain)
            verify(tenantEmailDomainRepository).findByIdEmailDomainIgnoreCaseAndVerifiedTrue("unknown.edu.tr");
            verify(tenantRepository).findByLegacyDomainIgnoreCase("unknown.edu.tr");
            // And the user landed on the default tenant resolved via slug.
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getTenant().getSlug()).isEqualTo("test-tenant");
        }
    }
}
