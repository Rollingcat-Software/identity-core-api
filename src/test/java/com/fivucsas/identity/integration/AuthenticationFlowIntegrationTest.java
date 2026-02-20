package com.fivucsas.identity.integration;

import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.query.GetUserByEmailQuery;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.service.AuthenticateUserService;
import com.fivucsas.identity.application.service.GetCurrentUserService;
import com.fivucsas.identity.application.service.RegisterUserService;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the authentication flow using TestContainers with real PostgreSQL.
 *
 * Replaces the previously @Disabled H2-based test. PostgreSQL is required because the
 * auth entities use PostgreSQL-specific column types (text[], jsonb) that H2 cannot
 * handle, and Flyway migrations must run against the real dialect.
 *
 * Test scenarios:
 * 1. Register new user — verifies persistence and password hashing
 * 2. Login with valid credentials — verifies JWT issuance
 * 3. Access protected endpoint via JWT — verifies token-to-user resolution
 * 4. Complete E2E flow — register → login → token → protected resource → refresh token
 * 5. Multiple login sessions — verifies independent refresh tokens per device
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("integration")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("Authentication Flow Integration Tests (PostgreSQL via Testcontainers)")
class AuthenticationFlowIntegrationTest {

    // Shared container across all tests in this class (static = reused, not recreated per test)
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_test")
            .withUsername("test")
            .withPassword("test");

    /**
     * Override datasource URL/credentials with the dynamically assigned container ports.
     * This is required because Testcontainers maps the container's 5432 to a random host port.
     */
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        // Switch driver back to the standard PostgreSQL driver when using DynamicPropertySource
        // (the tc: JDBC URL in application-integration.yml is only used if this source is absent)
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    @Autowired
    private RegisterUserService registerUserService;

    @Autowired
    private AuthenticateUserService authenticateUserService;

    @Autowired
    private GetCurrentUserService getCurrentUserService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenGenerationPort tokenGenerator;

    @Autowired
    private RefreshTokenService refreshTokenService;

    private static final String TEST_EMAIL = "integration.test@fivucsas.com";
    private static final String TEST_PASSWORD = "SecurePassword123!";
    private static final String TEST_FIRST_NAME = "Integration";
    private static final String TEST_LAST_NAME = "Test";
    private static final String TEST_IP_ADDRESS = "127.0.0.1";
    private static final String TEST_USER_AGENT = "Integration-Test-Agent/1.0";

    /**
     * Clean up the test user before each test so tests are independent and order-safe.
     * Using a programmatic delete rather than @Sql so the same logic works regardless
     * of whether data was left over from a previous failed run.
     */
    @BeforeEach
    @Transactional
    void setUp() {
        userRepository.findByEmail(TEST_EMAIL).ifPresent(user -> {
            refreshTokenService.revokeAllUserTokens(user);
            userRepository.delete(user);
        });
    }

    // -------------------------------------------------------------------------
    // Test 1 — Register
    // -------------------------------------------------------------------------

    @Test
    @Order(1)
    @DisplayName("register_WhenValidData_ShouldPersistUserAndReturnTokens")
    @Transactional
    void register_WhenValidData_ShouldPersistUserAndReturnTokens() {
        // Arrange
        RegisterUserCommand command = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();

        // Act
        AuthenticationResponse response = registerUserService.execute(command);

        // Assert — response shape
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotNull().isNotEmpty();
        assertThat(response.getRefreshToken()).isNotNull().isNotEmpty();
        assertThat(response.getUser()).isNotNull();
        assertThat(response.getUser().getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(response.getUser().getFirstName()).isEqualTo(TEST_FIRST_NAME);
        assertThat(response.getUser().getLastName()).isEqualTo(TEST_LAST_NAME);
        assertThat(response.getUser().getStatus()).isEqualTo("ACTIVE");
        assertThat(response.getUser().isBiometricEnrolled()).isFalse();

        // Assert — database state
        Optional<User> savedUser = userRepository.findByEmail(TEST_EMAIL);
        assertThat(savedUser).isPresent();
        // Password must be BCrypt-hashed, not stored in plain text
        assertThat(savedUser.get().getPasswordHash()).isNotEqualTo(TEST_PASSWORD);
        assertThat(savedUser.get().getPasswordHash()).startsWith("$2");
    }

    // -------------------------------------------------------------------------
    // Test 2 — Login
    // -------------------------------------------------------------------------

    @Test
    @Order(2)
    @DisplayName("login_WhenValidCredentials_ShouldReturnJwtTokens")
    @Transactional
    void login_WhenValidCredentials_ShouldReturnJwtTokens() {
        // Arrange — register the user first so the login has someone to authenticate
        registerUserService.execute(RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build());

        AuthenticateUserCommand loginCommand = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();

        // Act
        AuthenticationResponse response = authenticateUserService.execute(loginCommand);

        // Assert — tokens present and distinct
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isNotNull().isNotEmpty();
        assertThat(response.getRefreshToken()).isNotNull().isNotEmpty();
        assertThat(response.getAccessToken()).isNotEqualTo(response.getRefreshToken());

        // Assert — user info returned correctly
        assertThat(response.getUser()).isNotNull();
        assertThat(response.getUser().getEmail()).isEqualTo(TEST_EMAIL);

        // Assert — access token contains the expected subject (email)
        String emailFromToken = tokenGenerator.extractEmail(response.getAccessToken());
        assertThat(emailFromToken).isEqualTo(TEST_EMAIL);
    }

    // -------------------------------------------------------------------------
    // Test 3 — Access protected endpoint via JWT
    // -------------------------------------------------------------------------

    @Test
    @Order(3)
    @DisplayName("getCurrentUser_WhenTokenValid_ShouldReturnUserProfile")
    @Transactional
    void getCurrentUser_WhenTokenValid_ShouldReturnUserProfile() {
        // Arrange
        registerUserService.execute(RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build());

        AuthenticationResponse loginResponse = authenticateUserService.execute(
                AuthenticateUserCommand.builder()
                        .email(TEST_EMAIL)
                        .password(TEST_PASSWORD)
                        .ipAddress(TEST_IP_ADDRESS)
                        .userAgent(TEST_USER_AGENT)
                        .build());

        // Act — simulate what the JWT filter does: extract email, then call use case
        String emailFromToken = tokenGenerator.extractEmail(loginResponse.getAccessToken());
        UserResponse currentUser = getCurrentUserService.execute(
                GetUserByEmailQuery.builder().email(emailFromToken).build());

        // Assert
        assertThat(currentUser).isNotNull();
        assertThat(currentUser.getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(currentUser.getFirstName()).isEqualTo(TEST_FIRST_NAME);
        assertThat(currentUser.getLastName()).isEqualTo(TEST_LAST_NAME);
    }

    // -------------------------------------------------------------------------
    // Test 4 — Complete E2E flow
    // -------------------------------------------------------------------------

    @Test
    @Order(4)
    @DisplayName("completeAuthFlow_RegisterLoginAccessProtectedResource_ShouldSucceed")
    @Transactional
    void completeAuthFlow_RegisterLoginAccessProtectedResource_ShouldSucceed() {
        // Step 1: Register
        AuthenticationResponse registrationResponse = registerUserService.execute(
                RegisterUserCommand.builder()
                        .email(TEST_EMAIL)
                        .password(TEST_PASSWORD)
                        .firstName(TEST_FIRST_NAME)
                        .lastName(TEST_LAST_NAME)
                        .ipAddress(TEST_IP_ADDRESS)
                        .userAgent(TEST_USER_AGENT)
                        .build());

        assertThat(registrationResponse.getUser().getEmail()).isEqualTo(TEST_EMAIL);

        // Step 2: Login
        AuthenticationResponse authResponse = authenticateUserService.execute(
                AuthenticateUserCommand.builder()
                        .email(TEST_EMAIL)
                        .password(TEST_PASSWORD)
                        .ipAddress(TEST_IP_ADDRESS)
                        .userAgent(TEST_USER_AGENT)
                        .build());

        String accessToken = authResponse.getAccessToken();
        String refreshToken = authResponse.getRefreshToken();

        assertThat(accessToken).isNotNull();
        assertThat(refreshToken).isNotNull();

        // Step 3: Verify token subject
        String emailFromToken = tokenGenerator.extractEmail(accessToken);
        assertThat(emailFromToken).isEqualTo(TEST_EMAIL);

        // Step 4: Access protected resource (getCurrentUser via application service)
        UserResponse currentUser = getCurrentUserService.execute(
                GetUserByEmailQuery.builder().email(emailFromToken).build());

        assertThat(currentUser).isNotNull();
        assertThat(currentUser.getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(currentUser.getFirstName()).isEqualTo(TEST_FIRST_NAME);
        assertThat(currentUser.getStatus()).isEqualTo("ACTIVE");
        assertThat(currentUser.isBiometricEnrolled()).isFalse();
        assertThat(currentUser.getVerificationCount()).isEqualTo(0);

        // Step 5: Verify refresh token is persisted and valid
        RefreshToken foundToken = refreshTokenService.findByToken(refreshToken);
        assertThat(foundToken).isNotNull();
        assertThat(foundToken.getToken()).isEqualTo(refreshToken);
        assertThat(foundToken.isRevoked()).isFalse();
        assertThat(foundToken.isExpired()).isFalse();
    }

    // -------------------------------------------------------------------------
    // Test 5 — Multiple sessions
    // -------------------------------------------------------------------------

    @Test
    @Order(5)
    @DisplayName("login_FromMultipleDevices_ShouldCreateIndependentRefreshTokens")
    @Transactional
    void login_FromMultipleDevices_ShouldCreateIndependentRefreshTokens() {
        // Arrange
        registerUserService.execute(RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build());

        // Act — simulate two different devices logging in
        AuthenticationResponse session1 = authenticateUserService.execute(
                AuthenticateUserCommand.builder()
                        .email(TEST_EMAIL)
                        .password(TEST_PASSWORD)
                        .ipAddress("192.168.1.100")
                        .userAgent("Chrome/130 Windows")
                        .build());

        AuthenticationResponse session2 = authenticateUserService.execute(
                AuthenticateUserCommand.builder()
                        .email(TEST_EMAIL)
                        .password(TEST_PASSWORD)
                        .ipAddress("192.168.1.101")
                        .userAgent("Safari/17 macOS")
                        .build());

        // Assert — both sessions have valid access tokens
        assertThat(session1.getAccessToken()).isNotNull().isNotEmpty();
        assertThat(session2.getAccessToken()).isNotNull().isNotEmpty();

        // Refresh tokens must be unique across sessions
        assertThat(session1.getRefreshToken()).isNotEqualTo(session2.getRefreshToken());

        // Both refresh tokens must be resolvable from the repository
        RefreshToken token1 = refreshTokenService.findByToken(session1.getRefreshToken());
        RefreshToken token2 = refreshTokenService.findByToken(session2.getRefreshToken());

        assertThat(token1).isNotNull();
        assertThat(token2).isNotNull();
        assertThat(token1.getToken()).isNotEqualTo(token2.getToken());
    }

    // -------------------------------------------------------------------------
    // Teardown
    // -------------------------------------------------------------------------

    @AfterEach
    @Transactional
    void tearDown() {
        userRepository.findByEmail(TEST_EMAIL).ifPresent(user -> {
            refreshTokenService.revokeAllUserTokens(user);
            userRepository.delete(user);
        });
    }
}
