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
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-End Integration Test for Authentication Flow
 *
 * This test verifies the complete authentication workflow:
 * 1. Register a new user
 * 2. Login with credentials
 * 3. Receive JWT access token
 * 4. Access protected endpoint using token
 *
 * Uses H2 in-memory database for testing.
 */
@SpringBootTest
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("Authentication Flow Integration Tests")
@Disabled("H2 does not support PostgreSQL-specific types (text[], jsonb) used by auth entities. " +
          "Requires Testcontainers with PostgreSQL or a real database.")
class AuthenticationFlowIntegrationTest {

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
    private static final String TEST_USER_AGENT = "Integration-Test-Agent";

    @BeforeEach
    @Transactional
    void setUp() {
        // Clean up test user if exists from previous run
        userRepository.findByEmail(TEST_EMAIL).ifPresent(user -> {
            refreshTokenService.revokeAllUserTokens(user);
            userRepository.delete(user);
        });
    }

    @Test
    @Order(1)
    @DisplayName("Step 1: Register new user successfully")
    @Transactional
    void testStep1_RegisterUser() {
        // Given
        RegisterUserCommand registerCommand = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();

        // When
        AuthenticationResponse authResponse = registerUserService.execute(registerCommand);

        // Then
        assertThat(authResponse).isNotNull();
        assertThat(authResponse.getUser()).isNotNull();
        assertThat(authResponse.getUser().getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(authResponse.getUser().getFirstName()).isEqualTo(TEST_FIRST_NAME);
        assertThat(authResponse.getUser().getLastName()).isEqualTo(TEST_LAST_NAME);
        assertThat(authResponse.getUser().getStatus()).isEqualTo("ACTIVE");
        assertThat(authResponse.getUser().isBiometricEnrolled()).isFalse();
        assertThat(authResponse.getAccessToken()).isNotNull();
        assertThat(authResponse.getRefreshToken()).isNotNull();

        // Verify user exists in database
        Optional<User> savedUser = userRepository.findByEmail(TEST_EMAIL);
        assertThat(savedUser).isPresent();
        assertThat(savedUser.get().getPasswordHash()).isNotEqualTo(TEST_PASSWORD); // Password should be hashed
    }

    @Test
    @Order(2)
    @DisplayName("Step 2: Login with valid credentials and receive JWT token")
    @Transactional
    void testStep2_LoginAndReceiveToken() {
        // Given - First register the user
        RegisterUserCommand registerCommand = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();
        registerUserService.execute(registerCommand);

        // When - Login with credentials
        AuthenticateUserCommand loginCommand = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();

        AuthenticationResponse authResponse = authenticateUserService.execute(loginCommand);

        // Then
        assertThat(authResponse).isNotNull();
        assertThat(authResponse.getAccessToken()).isNotNull().isNotEmpty();
        assertThat(authResponse.getRefreshToken()).isNotNull().isNotEmpty();
        assertThat(authResponse.getUser()).isNotNull();
        assertThat(authResponse.getUser().getEmail()).isEqualTo(TEST_EMAIL);

        // Verify tokens are different
        assertThat(authResponse.getAccessToken()).isNotEqualTo(authResponse.getRefreshToken());

        // Verify access token is valid JWT
        String email = tokenGenerator.extractEmail(authResponse.getAccessToken());
        assertThat(email).isEqualTo(TEST_EMAIL);
    }

    @Test
    @Order(3)
    @DisplayName("Step 3: Access protected endpoint using JWT token")
    @Transactional
    void testStep3_AccessProtectedEndpoint() {
        // Given - Register and login to get token
        RegisterUserCommand registerCommand = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();
        registerUserService.execute(registerCommand);

        AuthenticateUserCommand loginCommand = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();

        AuthenticationResponse authResponse = authenticateUserService.execute(loginCommand);
        String accessToken = authResponse.getAccessToken();

        // When - Access protected endpoint (getCurrentUser) using token
        String emailFromToken = tokenGenerator.extractEmail(accessToken);
        GetUserByEmailQuery query = GetUserByEmailQuery.builder().email(emailFromToken).build();
        UserResponse currentUser = getCurrentUserService.execute(query);

        // Then
        assertThat(currentUser).isNotNull();
        assertThat(currentUser.getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(currentUser.getFirstName()).isEqualTo(TEST_FIRST_NAME);
        assertThat(currentUser.getLastName()).isEqualTo(TEST_LAST_NAME);
    }

    @Test
    @Order(4)
    @DisplayName("Complete E2E Flow: Register → Login → Access Protected Resource")
    @Transactional
    void testCompleteAuthenticationFlow() {
        // Step 1: Register User
        RegisterUserCommand registerCommand = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();

        AuthenticationResponse registrationResponse = registerUserService.execute(registerCommand);
        assertThat(registrationResponse).isNotNull();
        assertThat(registrationResponse.getUser()).isNotNull();
        assertThat(registrationResponse.getUser().getEmail()).isEqualTo(TEST_EMAIL);

        // Step 2: Login and Get JWT
        AuthenticateUserCommand loginCommand = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();

        AuthenticationResponse authResponse = authenticateUserService.execute(loginCommand);
        assertThat(authResponse).isNotNull();
        assertThat(authResponse.getAccessToken()).isNotNull();

        String accessToken = authResponse.getAccessToken();
        String refreshToken = authResponse.getRefreshToken();

        // Step 3: Verify Access Token
        String emailFromToken = tokenGenerator.extractEmail(accessToken);
        assertThat(emailFromToken).isEqualTo(TEST_EMAIL);

        // Step 4: Access Protected Endpoint
        GetUserByEmailQuery query = GetUserByEmailQuery.builder().email(emailFromToken).build();
        UserResponse currentUser = getCurrentUserService.execute(query);
        assertThat(currentUser).isNotNull();
        assertThat(currentUser.getEmail()).isEqualTo(TEST_EMAIL);
        assertThat(currentUser.getFirstName()).isEqualTo(TEST_FIRST_NAME);

        // Step 5: Verify Refresh Token Exists
        RefreshToken foundToken = refreshTokenService.findByToken(refreshToken);
        assertThat(foundToken).isNotNull();
        assertThat(foundToken.getToken()).isEqualTo(refreshToken);

        // Verify complete user profile
        assertThat(currentUser.getStatus()).isEqualTo("ACTIVE");
        assertThat(currentUser.isBiometricEnrolled()).isFalse();
        assertThat(currentUser.getVerificationCount()).isEqualTo(0);
    }

    @Test
    @Order(5)
    @DisplayName("Multiple login sessions should create multiple refresh tokens")
    @Transactional
    void testMultipleLoginSessions() {
        // Given - Register user
        RegisterUserCommand registerCommand = RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .ipAddress(TEST_IP_ADDRESS)
                .userAgent(TEST_USER_AGENT)
                .build();
        registerUserService.execute(registerCommand);

        // When - Login from different devices
        AuthenticateUserCommand login1 = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .ipAddress("192.168.1.100")
                .userAgent("Chrome/Windows")
                .build();

        AuthenticateUserCommand login2 = AuthenticateUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .ipAddress("192.168.1.101")
                .userAgent("Safari/MacOS")
                .build();

        AuthenticationResponse auth1 = authenticateUserService.execute(login1);
        AuthenticationResponse auth2 = authenticateUserService.execute(login2);

        // Then - Both sessions should have valid tokens
        assertThat(auth1.getAccessToken()).isNotNull();
        assertThat(auth2.getAccessToken()).isNotNull();
        assertThat(auth1.getRefreshToken()).isNotEqualTo(auth2.getRefreshToken());

        // Both refresh tokens should be valid
        RefreshToken token1 = refreshTokenService.findByToken(auth1.getRefreshToken());
        RefreshToken token2 = refreshTokenService.findByToken(auth2.getRefreshToken());
        assertThat(token1).isNotNull();
        assertThat(token2).isNotNull();
    }

    @AfterEach
    @Transactional
    void tearDown() {
        // Clean up after each test
        userRepository.findByEmail(TEST_EMAIL).ifPresent(user -> {
            refreshTokenService.revokeAllUserTokens(user);
            userRepository.delete(user);
        });
    }
}
