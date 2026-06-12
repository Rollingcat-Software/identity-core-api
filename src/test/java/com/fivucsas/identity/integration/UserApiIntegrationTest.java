package com.fivucsas.identity.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.dto.LoginRequest;
import com.fivucsas.identity.dto.RegisterRequest;
import com.fivucsas.identity.repository.RefreshTokenRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * REST API integration tests for auth and user management endpoints.
 *
 * These tests exercise the full Spring MVC stack — security filters, controllers,
 * application services, repositories — against a real PostgreSQL instance managed
 * by Testcontainers. Flyway migrations run automatically on startup, so the schema
 * matches production exactly.
 *
 * Endpoints under test:
 *   POST /api/v1/auth/register  — register a new user
 *   POST /api/v1/auth/login     — authenticate and obtain JWT
 *   GET  /api/v1/auth/me        — fetch current user (requires valid JWT)
 *   POST /api/v1/auth/refresh   — rotate refresh token
 *   POST /api/v1/auth/logout    — revoke refresh token
 *   GET  /api/v1/users          — list all users (requires user:read permission)
 *   GET  /api/v1/users/{id}     — fetch single user by ID
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("User API Integration Tests (PostgreSQL via Testcontainers)")
class UserApiIntegrationTest {

    // Shared container — started once for all tests in this class
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_api_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RateLimitService rateLimitService;

    /**
     * Loopback IP that {@link org.springframework.mock.web.MockHttpServletRequest}
     * reports for every MockMvc call (no {@code X-Forwarded-For} is sent), so it is
     * the bucket key {@code RateLimitInterceptor} throttles against.
     */
    private static final String MOCK_MVC_CLIENT_IP = "127.0.0.1";

    private static final String API_EMAIL    = "apitest@fivucsas.com";
    private static final String API_PASSWORD = "ApiTest123!";
    private static final String FIRST_NAME   = "Api";
    private static final String LAST_NAME    = "Test";

    // -------------------------------------------------------------------------
    // State shared across tests (kept minimal; each test re-derives what it needs)
    // -------------------------------------------------------------------------

    /** Populated once in the register test, reused by downstream tests. */
    private static String registeredUserId;
    private static String accessToken;
    private static String refreshToken;

    @BeforeEach
    @Transactional
    void cleanUp() {
        // Remove any leftover user from a previous run before each test
        userRepository.findByEmail(API_EMAIL).ifPresent(user -> {
            refreshTokenService.revokeAllUserTokens(user);
            userRepository.delete(user);
        });
        // Test isolation for the IP-keyed rate limiter. Every test in this class
        // hits /auth/register and/or /auth/login from the SAME MockMvc loopback IP,
        // and the production buckets are tiny (registration = 5/hour, login = 10/5min
        // per IP) and span the whole class run. Without a reset the shared
        // registerViaApi helper trips REGISTRATION after the 5th test and the rest
        // cascade into HTTP 429 — a test-isolation artifact, NOT a product bug. Drop
        // the per-IP buckets before each test so each starts with a full allowance.
        // This only clears the in-memory test buckets; it does NOT weaken production
        // rate-limiting (the limits themselves are unchanged).
        rateLimitService.resetRateLimit(MOCK_MVC_CLIENT_IP, RateLimitService.RateLimitType.REGISTRATION);
        rateLimitService.resetRateLimit(MOCK_MVC_CLIENT_IP, RateLimitService.RateLimitType.LOGIN);
        // Reset shared state
        registeredUserId = null;
        accessToken = null;
        refreshToken = null;
    }

    // =========================================================================
    // POST /api/v1/auth/register
    // =========================================================================

    @Test
    @Order(1)
    @DisplayName("register_WhenValidRequest_ShouldReturn200WithTokens")
    void register_WhenValidRequest_ShouldReturn200WithTokens() throws Exception {
        RegisterRequest request = buildRegisterRequest(API_EMAIL, API_PASSWORD, FIRST_NAME, LAST_NAME);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.user.email").value(API_EMAIL))
                .andExpect(jsonPath("$.user.firstName").value(FIRST_NAME))
                .andExpect(jsonPath("$.user.lastName").value(LAST_NAME))
                .andExpect(jsonPath("$.user.status").value("ACTIVE"))
                .andExpect(jsonPath("$.user.biometricEnrolled").value(false));
    }

    @Test
    @Order(2)
    @DisplayName("register_WhenDuplicateEmail_ShouldReturn409")
    void register_WhenDuplicateEmail_ShouldReturn409() throws Exception {
        RegisterRequest request = buildRegisterRequest(API_EMAIL, API_PASSWORD, FIRST_NAME, LAST_NAME);

        // First registration
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Duplicate registration with the same email
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }

    @Test
    @Order(3)
    @DisplayName("register_WhenMissingFields_ShouldReturn400")
    void register_WhenMissingFields_ShouldReturn400() throws Exception {
        // Missing firstName and lastName — both are @NotBlank
        String incompleteJson = "{\"email\":\"apitest@fivucsas.com\",\"password\":\"ApiTest123!\"}";

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(incompleteJson))
                .andExpect(status().isBadRequest());
    }

    @Test
    @Order(4)
    @DisplayName("register_WhenInvalidEmailFormat_ShouldReturn400")
    void register_WhenInvalidEmailFormat_ShouldReturn400() throws Exception {
        String badEmail = "{\"email\":\"not-an-email\",\"password\":\"ApiTest123!\","
                + "\"firstName\":\"Api\",\"lastName\":\"Test\"}";

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(badEmail))
                .andExpect(status().isBadRequest());
    }

    // =========================================================================
    // POST /api/v1/auth/login
    // =========================================================================

    @Test
    @Order(5)
    @DisplayName("login_WhenValidCredentials_ShouldReturn200WithJwt")
    void login_WhenValidCredentials_ShouldReturn200WithJwt() throws Exception {
        // Pre-condition: user must exist
        registerViaApi(API_EMAIL, API_PASSWORD);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(API_EMAIL);
        loginRequest.setPassword(API_PASSWORD);

        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").isNumber())
                .andExpect(jsonPath("$.user.email").value(API_EMAIL))
                .andReturn();

        // Extract tokens for downstream assertions
        String body = result.getResponse().getContentAsString();
        accessToken  = objectMapper.readTree(body).get("accessToken").asText();
        refreshToken = objectMapper.readTree(body).get("refreshToken").asText();
    }

    @Test
    @Order(6)
    @DisplayName("login_WhenWrongPassword_ShouldReturn401")
    void login_WhenWrongPassword_ShouldReturn401() throws Exception {
        registerViaApi(API_EMAIL, API_PASSWORD);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(API_EMAIL);
        loginRequest.setPassword("WrongPassword999!");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(7)
    @DisplayName("login_WhenUnregisteredEmail_ShouldReturn401")
    void login_WhenUnregisteredEmail_ShouldReturn401() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("ghost@fivucsas.com");
        loginRequest.setPassword("AnyPassword123!");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    // =========================================================================
    // GET /api/v1/auth/me
    // =========================================================================

    @Test
    @Order(8)
    @DisplayName("getMe_WhenValidToken_ShouldReturn200WithUserProfile")
    void getMe_WhenValidToken_ShouldReturn200WithUserProfile() throws Exception {
        String token = registerAndLogin(API_EMAIL, API_PASSWORD);

        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(API_EMAIL))
                .andExpect(jsonPath("$.firstName").value(FIRST_NAME))
                .andExpect(jsonPath("$.lastName").value(LAST_NAME))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    @Order(9)
    @DisplayName("getMe_WhenNoToken_ShouldReturn401")
    void getMe_WhenNoToken_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(10)
    @DisplayName("getMe_WhenInvalidToken_ShouldReturn401")
    void getMe_WhenInvalidToken_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer totally.invalid.token"))
                .andExpect(status().isUnauthorized());
    }

    // =========================================================================
    // POST /api/v1/auth/refresh
    // =========================================================================

    @Test
    @Order(11)
    @DisplayName("refreshToken_WhenValidRefreshToken_ShouldReturn200WithNewTokens")
    void refreshToken_WhenValidRefreshToken_ShouldReturn200WithNewTokens() throws Exception {
        MvcResult loginResult = registerAndLoginMvcResult(API_EMAIL, API_PASSWORD);
        String body = loginResult.getResponse().getContentAsString();
        String originalRefreshToken = objectMapper.readTree(body).get("refreshToken").asText();
        String originalAccessToken  = objectMapper.readTree(body).get("accessToken").asText();

        String refreshBody = "{\"refreshToken\":\"" + originalRefreshToken + "\"}";

        MvcResult refreshResult = mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        // New tokens must be different from the originals (token rotation)
        String newBody = refreshResult.getResponse().getContentAsString();
        String newAccessToken  = objectMapper.readTree(newBody).get("accessToken").asText();
        String newRefreshToken = objectMapper.readTree(newBody).get("refreshToken").asText();

        Assertions.assertNotEquals(originalAccessToken,  newAccessToken,
                "Rotated access token should differ from the original");
        Assertions.assertNotEquals(originalRefreshToken, newRefreshToken,
                "Rotated refresh token should differ from the original");
    }

    @Test
    @Order(12)
    @DisplayName("refreshToken_WhenInvalidToken_ShouldReturn401")
    void refreshToken_WhenInvalidToken_ShouldReturn401() throws Exception {
        String body = "{\"refreshToken\":\"00000000-dead-beef-0000-000000000000\"}";

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized());
    }

    // =========================================================================
    // POST /api/v1/auth/logout
    // =========================================================================

    @Test
    @Order(13)
    @DisplayName("logout_WhenValidRefreshToken_ShouldReturn200AndRevokeToken")
    void logout_WhenValidRefreshToken_ShouldReturn200AndRevokeToken() throws Exception {
        MvcResult loginResult = registerAndLoginMvcResult(API_EMAIL, API_PASSWORD);
        String loginBody = loginResult.getResponse().getContentAsString();
        String rt = objectMapper.readTree(loginBody).get("refreshToken").asText();

        String logoutBody = "{\"refreshToken\":\"" + rt + "\"}";

        mockMvc.perform(post("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logoutBody))
                .andExpect(status().isOk());

        // After logout the refresh token must be revoked; a refresh attempt should fail
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logoutBody))
                .andExpect(status().isUnauthorized());
    }

    // =========================================================================
    // GET /api/v1/users  (requires user:read permission)
    // =========================================================================

    @Test
    @Order(14)
    @DisplayName("getUsers_WhenNoToken_ShouldReturn401")
    void getUsers_WhenNoToken_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(15)
    @DisplayName("getUsers_WhenAuthenticatedWithoutAdminPermission_ShouldReturn403")
    void getUsers_WhenAuthenticatedWithoutAdminPermission_ShouldReturn403() throws Exception {
        // A freshly registered user has no 'user:read' permission, so expect 403
        String token = registerAndLogin(API_EMAIL, API_PASSWORD);

        mockMvc.perform(get("/api/v1/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    // =========================================================================
    // GET /api/v1/users/{id}
    // =========================================================================

    @Test
    @Order(16)
    @DisplayName("getUserById_WhenNoToken_ShouldReturn401")
    void getUserById_WhenNoToken_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/users/some-random-id"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(17)
    @DisplayName("getUserById_WhenCurrentUserAccessesOwnProfile_ShouldReturn200")
    void getUserById_WhenCurrentUserAccessesOwnProfile_ShouldReturn200() throws Exception {
        // Register, login, then call GET /me to find own ID
        String token = registerAndLogin(API_EMAIL, API_PASSWORD);

        MvcResult meResult = mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();

        String meBody = meResult.getResponse().getContentAsString();
        String userId = objectMapper.readTree(meBody).get("id").asText();

        // GET /api/v1/users/{id} — the security rule allows the user to access their own resource
        mockMvc.perform(get("/api/v1/users/{id}", userId)
                        .header("Authorization", "Bearer " + token))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId))
                .andExpect(jsonPath("$.email").value(API_EMAIL))
                .andExpect(jsonPath("$.firstName").value(FIRST_NAME))
                .andExpect(jsonPath("$.lastName").value(LAST_NAME));
    }

    @Test
    @Order(18)
    @DisplayName("getUserById_WhenAccessingOtherUserWithoutPermission_ShouldReturn403")
    void getUserById_WhenAccessingOtherUserWithoutPermission_ShouldReturn403() throws Exception {
        // Register two users
        String token = registerAndLogin(API_EMAIL, API_PASSWORD);

        // Find the ID of a system user that is NOT the current user (seeded by V15 migration)
        // If no such user exists, this test is skipped gracefully via the response check
        mockMvc.perform(get("/api/v1/users/00000000-0000-0000-0000-000000000001")
                        .header("Authorization", "Bearer " + token))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    // Expect either 403 (no permission to read others) or 404 (ID does not exist)
                    Assertions.assertTrue(
                            status == 403 || status == 404,
                            "Expected 403 or 404 but got: " + status
                    );
                });
    }

    // =========================================================================
    // GET /api/v1/auth/health  (public endpoint)
    // =========================================================================

    @Test
    @Order(19)
    @DisplayName("healthCheck_WhenCalled_ShouldReturn200WithoutAuth")
    void healthCheck_WhenCalled_ShouldReturn200WithoutAuth() throws Exception {
        mockMvc.perform(get("/api/v1/auth/health"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("healthy")));
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /**
     * Register a user via the REST API and discard the response body.
     */
    private void registerViaApi(String email, String password) throws Exception {
        RegisterRequest request = buildRegisterRequest(email, password, FIRST_NAME, LAST_NAME);
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    /**
     * Register and login in sequence, returning the access token string.
     */
    private String registerAndLogin(String email, String password) throws Exception {
        MvcResult result = registerAndLoginMvcResult(email, password);
        String body = result.getResponse().getContentAsString();
        return objectMapper.readTree(body).get("accessToken").asText();
    }

    /**
     * Register and login in sequence, returning the full MvcResult from the login call.
     */
    private MvcResult registerAndLoginMvcResult(String email, String password) throws Exception {
        registerViaApi(email, password);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail(email);
        loginRequest.setPassword(password);

        return mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();
    }

    /**
     * Build a RegisterRequest DTO.
     */
    private RegisterRequest buildRegisterRequest(
            String email, String password, String firstName, String lastName) {
        RegisterRequest request = new RegisterRequest();
        request.setEmail(email);
        request.setPassword(password);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        return request;
    }

    // =========================================================================
    // Teardown
    // =========================================================================

    @AfterEach
    @Transactional
    void tearDown() {
        userRepository.findByEmail(API_EMAIL).ifPresent(user -> {
            refreshTokenService.revokeAllUserTokens(user);
            userRepository.delete(user);
        });
    }
}
