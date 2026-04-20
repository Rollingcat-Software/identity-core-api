package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.dto.command.AuthenticateUserCommand;
import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.port.input.AuthenticateUserUseCase;
import com.fivucsas.identity.application.port.input.GetCurrentUserUseCase;
import com.fivucsas.identity.application.port.input.LogoutUserUseCase;
import com.fivucsas.identity.application.port.input.RefreshTokenUseCase;
import com.fivucsas.identity.application.port.input.RegisterUserUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.application.port.output.NfcCardRepositoryPort;
import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.application.service.EnrollmentHealthService;
import com.fivucsas.identity.domain.exception.DuplicateEmailException;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.dto.LoginRequest;
import com.fivucsas.identity.dto.RegisterRequest;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.service.RefreshTokenService;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import org.junit.jupiter.api.BeforeEach;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for AuthController.
 *
 * Tests authentication endpoints with various scenarios:
 * - Registration (success, duplicate email, invalid data)
 * - Login (success, invalid credentials)
 * - Token refresh (success, invalid token)
 * - Logout (success)
 *
 * Uses MockMvc for controller testing and Mockito for mocking services.
 */
@WebMvcTest(controllers = AuthController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("Auth Controller Tests")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private RegisterUserUseCase registerUserUseCase;

    @MockBean
    private AuthenticateUserUseCase authenticateUserUseCase;

    @MockBean
    private RefreshTokenUseCase refreshTokenUseCase;

    @MockBean
    private LogoutUserUseCase logoutUserUseCase;

    @MockBean
    private GetCurrentUserUseCase getCurrentUserUseCase;

    // Security beans needed for context loading
    @MockBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @MockBean
    private UserDetailsService userDetailsService;

    @MockBean
    private RateLimitService rateLimitService;

    @MockBean
    private TenantRepository tenantRepository;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private OtpService otpService;

    @MockBean
    private EmailService emailService;

    @MockBean
    private SmsService smsService;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private CachePort cachePort;

    @MockBean
    private RedisConnectionFactory redisConnectionFactory;

    @MockBean
    private StringRedisTemplate stringRedisTemplate;

    // AuthController dependencies grown since last CI run (ubuntu-latest
    // surfaced the drift). Keep in sync with AuthController constructor.
    @MockBean
    private EnrollmentHealthService enrollmentHealthService;

    @MockBean
    private NfcCardRepositoryPort nfcCardRepository;

    @MockBean
    private QrCodeService qrCodeService;

    @MockBean
    private WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;

    @MockBean
    private AuditLogPort auditLogPort;

    @MockBean
    private AuthFlowRepositoryPort authFlowRepository;

    @MockBean
    private TotpService totpService;

    @MockBean
    private BiometricServicePort biometricService;

    @MockBean
    private WebAuthnService webAuthnService;

    @MockBean
    private MfaSessionRepository mfaSessionRepository;

    @MockBean
    private TokenGenerationPort tokenGenerator;

    @MockBean
    private RefreshTokenService refreshTokenService;

    @MockBean
    private UserEnrollmentRepository userEnrollmentRepository;

    @MockBean
    private com.fivucsas.identity.security.TotpSecretCipher totpSecretCipher;

    // Test Data
    private static final String TEST_EMAIL = "test@fivucsas.com";
    private static final String TEST_PASSWORD = "SecurePassword123!";
    private static final String TEST_FIRST_NAME = "Test";
    private static final String TEST_LAST_NAME = "User";
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
    private static final String TEST_REFRESH_TOKEN = "550e8400-e29b-41d4-a716-446655440000";

    @BeforeEach
    void setUp() {
        // Configure rate limit service to allow all requests in tests
        when(rateLimitService.allowLoginAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowRegistrationAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowMfaStepAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowMfaOtpSend(anyString())).thenReturn(true);
        when(rateLimitService.allowMfaQrGenerate(anyString())).thenReturn(true);
    }

    // ============== REGISTRATION TESTS ==============

    @Test
    @DisplayName("POST /api/v1/auth/register - Success (200)")
    void testRegister_Success() throws Exception {
        // Arrange - Use API DTO
        RegisterRequest request = new RegisterRequest();
        request.setEmail(TEST_EMAIL);
        request.setPassword(TEST_PASSWORD);
        request.setFirstName(TEST_FIRST_NAME);
        request.setLastName(TEST_LAST_NAME);

        UserResponse userResponse = UserResponse.builder()
                .id("123e4567-e89b-12d3-a456-426614174000")
                .email(TEST_EMAIL)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .status("ACTIVE")
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .createdAt(java.time.Instant.now())
                .updatedAt(java.time.Instant.now())
                .build();

        AuthenticationResponse authResponse = AuthenticationResponse.of(
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                86400000L,
                userResponse
        );

        when(registerUserUseCase.execute(any(RegisterUserCommand.class)))
                .thenReturn(authResponse);

        // Act & Assert - Controller returns 201 Created for new user registration
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").value(TEST_ACCESS_TOKEN))
                .andExpect(jsonPath("$.refreshToken").value(TEST_REFRESH_TOKEN))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.user.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.user.firstName").value(TEST_FIRST_NAME));

        verify(registerUserUseCase, times(1)).execute(any(RegisterUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/v1/auth/register - Duplicate Email (409)")
    void testRegister_DuplicateEmail() throws Exception {
        // Arrange
        RegisterRequest request = new RegisterRequest();
        request.setEmail(TEST_EMAIL);
        request.setPassword(TEST_PASSWORD);
        request.setFirstName(TEST_FIRST_NAME);
        request.setLastName(TEST_LAST_NAME);

        when(registerUserUseCase.execute(any(RegisterUserCommand.class)))
                .thenThrow(new DuplicateEmailException(TEST_EMAIL));

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());

        verify(registerUserUseCase, times(1)).execute(any(RegisterUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/v1/auth/register - Missing Required Fields (400)")
    void testRegister_MissingFields() throws Exception {
        // Arrange - Missing email and password (validation should fail)
        String invalidJson = "{\"firstName\":\"Test\",\"lastName\":\"User\"}";

        // Act & Assert - Validation should reject before calling use case
        mockMvc.perform(post("/api/v1/auth/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidJson))
                .andExpect(status().isBadRequest());

        verify(registerUserUseCase, never()).execute(any(RegisterUserCommand.class));
    }

    // ============== LOGIN TESTS ==============

    @Test
    @DisplayName("POST /api/v1/auth/login - Success (200)")
    void testLogin_Success() throws Exception {
        // Arrange - Use API DTO
        LoginRequest request = new LoginRequest();
        request.setEmail(TEST_EMAIL);
        request.setPassword(TEST_PASSWORD);

        UserResponse userResponse = UserResponse.builder()
                .id("123e4567-e89b-12d3-a456-426614174000")
                .email(TEST_EMAIL)
                .firstName(TEST_FIRST_NAME)
                .lastName(TEST_LAST_NAME)
                .status("ACTIVE")
                .isBiometricEnrolled(true)
                .verificationCount(5)
                .build();

        AuthenticationResponse authResponse = AuthenticationResponse.of(
                TEST_ACCESS_TOKEN,
                TEST_REFRESH_TOKEN,
                86400000L,
                userResponse
        );

        when(authenticateUserUseCase.execute(any(AuthenticateUserCommand.class)))
                .thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value(TEST_ACCESS_TOKEN))
                .andExpect(jsonPath("$.refreshToken").value(TEST_REFRESH_TOKEN))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.user.email").value(TEST_EMAIL))
                .andExpect(jsonPath("$.user.biometricEnrolled").value(true))
                .andExpect(jsonPath("$.user.verificationCount").value(5));

        verify(authenticateUserUseCase, times(1)).execute(any(AuthenticateUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/v1/auth/login - Invalid Credentials (401)")
    void testLogin_InvalidCredentials() throws Exception {
        // Arrange
        LoginRequest request = new LoginRequest();
        request.setEmail(TEST_EMAIL);
        request.setPassword("WrongPassword123!");

        when(authenticateUserUseCase.execute(any(AuthenticateUserCommand.class)))
                .thenThrow(new InvalidCredentialsException());

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());

        verify(authenticateUserUseCase, times(1)).execute(any(AuthenticateUserCommand.class));
    }

    @Test
    @DisplayName("POST /api/v1/auth/login - Missing Credentials (400)")
    void testLogin_MissingCredentials() throws Exception {
        // Arrange - Missing password
        String invalidJson = "{\"email\":\"test@fivucsas.com\"}";

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidJson))
                .andExpect(status().isBadRequest());

        verify(authenticateUserUseCase, never()).execute(any(AuthenticateUserCommand.class));
    }

    // ============== TOKEN REFRESH TESTS ==============

    @Test
    @DisplayName("POST /api/v1/auth/refresh - Success (200)")
    @WithMockUser
    void testRefreshToken_Success() throws Exception {
        // Arrange
        String requestJson = "{\"refreshToken\":\"" + TEST_REFRESH_TOKEN + "\"}";

        AuthenticationResponse authResponse = AuthenticationResponse.of(
                "new-access-token",
                "new-refresh-token",
                86400000L,
                UserResponse.builder()
                        .id("123")
                        .email(TEST_EMAIL)
                        .firstName(TEST_FIRST_NAME)
                        .lastName(TEST_LAST_NAME)
                        .status("ACTIVE")
                        .build()
        );

        when(refreshTokenUseCase.execute(any()))
                .thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));

        verify(refreshTokenUseCase, times(1)).execute(any());
    }

    @Test
    @DisplayName("POST /api/v1/auth/refresh - Invalid Token (401)")
    @WithMockUser
    void testRefreshToken_InvalidToken() throws Exception {
        // Arrange
        String requestJson = "{\"refreshToken\":\"invalid-token\"}";

        when(refreshTokenUseCase.execute(any()))
                .thenThrow(new InvalidCredentialsException("Invalid refresh token"));

        // Act & Assert
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isUnauthorized());

        verify(refreshTokenUseCase, times(1)).execute(any());
    }

    // ============== LOGOUT TESTS ==============

    @Test
    @DisplayName("POST /api/v1/auth/logout - Success (200)")
    void testLogout_Success() throws Exception {
        // Arrange
        String requestJson = "{\"refreshToken\":\"" + TEST_REFRESH_TOKEN + "\"}";

        doNothing().when(logoutUserUseCase).execute(any());

        // Act & Assert - Controller returns 204 No Content on successful logout.
        // Provide principal directly since addFilters=false prevents
        // SecurityContextHolderAwareRequestFilter from wrapping the request.
        mockMvc.perform(post("/api/v1/auth/logout")
                        .with(csrf())
                        .principal(new UsernamePasswordAuthenticationToken(TEST_EMAIL, null, java.util.Collections.emptyList()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isNoContent());

        verify(logoutUserUseCase, times(1)).execute(any());
    }

    // ============== MFA RATE LIMIT TESTS (PR #17 Copilot follow-up) ==============

    @Test
    @DisplayName("POST /api/v1/auth/mfa/step - Rate Limited (429 + Retry-After)")
    void testMfaStep_RateLimited() throws Exception {
        when(rateLimitService.allowMfaStepAttempt(anyString())).thenReturn(false);
        when(rateLimitService.getSecondsUntilRefill(anyString(),
                eq(RateLimitService.RateLimitType.MFA_STEP))).thenReturn(42L);

        mockMvc.perform(post("/api/v1/auth/mfa/step")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionToken\":\"x\",\"method\":\"EMAIL_OTP\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "42"));
    }

    @Test
    @DisplayName("POST /api/v1/auth/mfa/send-otp - Rate Limited (429 + Retry-After)")
    void testMfaSendOtp_RateLimited() throws Exception {
        when(rateLimitService.allowMfaOtpSend(anyString())).thenReturn(false);
        when(rateLimitService.getSecondsUntilRefill(anyString(),
                eq(RateLimitService.RateLimitType.MFA_OTP_SEND))).thenReturn(120L);

        mockMvc.perform(post("/api/v1/auth/mfa/send-otp")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionToken\":\"x\",\"method\":\"EMAIL_OTP\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "120"));
    }

    @Test
    @DisplayName("POST /api/v1/auth/mfa/qr-generate - Rate Limited (429 + Retry-After)")
    void testMfaQrGenerate_RateLimited() throws Exception {
        when(rateLimitService.allowMfaQrGenerate(anyString())).thenReturn(false);
        when(rateLimitService.getSecondsUntilRefill(anyString(),
                eq(RateLimitService.RateLimitType.MFA_QR))).thenReturn(60L);

        mockMvc.perform(post("/api/v1/auth/mfa/qr-generate")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionToken\":\"x\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"));
    }
}
