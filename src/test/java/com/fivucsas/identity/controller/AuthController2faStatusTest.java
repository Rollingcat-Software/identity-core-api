package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
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
import com.fivucsas.identity.security.TotpSecretCipher;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Pinned regression test for the P1 hygiene wave (2026-05-07): the
 * {@code /auth/verify-email}, {@code /auth/verify-phone}, {@code /auth/2fa/verify}
 * and {@code /auth/2fa/verify-method} endpoints used to return HTTP 200 with
 * {@code success:false} for auth failures, which made them invisible to
 * 4xx-rate observability and confused intermediary HTTP tooling. This test
 * pins the new contract:
 *
 * <ul>
 *   <li>Invalid/expired email OTP → {@code 401 Unauthorized}</li>
 *   <li>Invalid/expired phone OTP → {@code 401 Unauthorized}</li>
 *   <li>Invalid/expired 2FA email OTP → {@code 401 Unauthorized}</li>
 *   <li>Failed multi-method 2FA verify (any method) → {@code 401 Unauthorized}</li>
 * </ul>
 *
 * <p>Body shape is preserved: callers still receive
 * {@code {"success": false, "message": "..."}} so existing frontend code that
 * unwraps either branch (e.g. {@code TwoFactorVerification.tsx}) continues to
 * work. Only the HTTP status changes.</p>
 */
@WebMvcTest(controllers = AuthController.class,
        excludeAutoConfiguration = {
                org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
                org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("AuthController — /verify* and /2fa/verify* HTTP status corrections (P1)")
class AuthController2faStatusTest {

    private static final String TEST_EMAIL = "test@fivucsas.com";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    // Use-case ports — required by AuthController constructor.
    @MockBean private RegisterUserUseCase registerUserUseCase;
    @MockBean private AuthenticateUserUseCase authenticateUserUseCase;
    @MockBean private RefreshTokenUseCase refreshTokenUseCase;
    @MockBean private LogoutUserUseCase logoutUserUseCase;
    @MockBean private GetCurrentUserUseCase getCurrentUserUseCase;

    // Security wiring (filter is excluded, but the filter bean itself is still injected).
    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private RateLimitService rateLimitService;

    // Repositories.
    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
    @MockBean private MfaSessionRepository mfaSessionRepository;
    @MockBean private UserEnrollmentRepository userEnrollmentRepository;

    // Services.
    @MockBean private OtpService otpService;
    @MockBean private EmailService emailService;
    @MockBean private SmsService smsService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;
    @MockBean private EnrollmentHealthService enrollmentHealthService;
    @MockBean private NfcCardRepositoryPort nfcCardRepository;
    @MockBean private QrCodeService qrCodeService;
    @MockBean private WebAuthnCredentialRepositoryPort webAuthnCredentialRepository;
    @MockBean private AuditLogPort auditLogPort;
    @MockBean private AuthFlowRepositoryPort authFlowRepository;
    @MockBean private TotpService totpService;
    @MockBean private BiometricServicePort biometricService;
    @MockBean private WebAuthnService webAuthnService;
    @MockBean private TokenGenerationPort tokenGenerator;
    @MockBean private RefreshTokenService refreshTokenService;
    @MockBean private TotpSecretCipher totpSecretCipher;
    @MockBean private com.fivucsas.identity.application.service.mfa.VerifyMfaStepService verifyMfaStepService;
    @MockBean private com.fivucsas.identity.application.service.LoginConfigService loginConfigService;

    @BeforeEach
    void setUp() {
        when(rateLimitService.allowLoginAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowRegistrationAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowMfaStepAttempt(anyString())).thenReturn(true);
    }

    private static Authentication authFor(String email) {
        return new UsernamePasswordAuthenticationToken(
                email, "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private User userMock(UUID userId) {
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn(TEST_EMAIL);
        when(user.getStatus()).thenReturn(UserStatus.ACTIVE);
        when(user.getFirstName()).thenReturn("Test");
        when(user.getLastName()).thenReturn("User");
        when(user.isEmailVerified()).thenReturn(false);
        when(user.isPhoneVerified()).thenReturn(false);
        when(user.isBiometricEnrolled()).thenReturn(false);
        when(user.getVerificationCount()).thenReturn(0);
        return user;
    }

    @Test
    @DisplayName("POST /auth/verify-email - invalid OTP returns 401 (was 200/success:false)")
    void verifyEmail_invalidOtp_returns401() throws Exception {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        // user has not yet verified email — controller will reach OTP check.
        when(user.isEmailVerified()).thenReturn(false);
        when(otpService.validate(anyString(), anyString())).thenReturn(false);

        String body = "{\"code\":\"000000\"}";
        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .with(csrf())
                        .principal(authFor(TEST_EMAIL))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Invalid or expired verification code"));
    }

    @Test
    @DisplayName("POST /auth/verify-phone - invalid OTP returns 401 (was 200/success:false)")
    void verifyPhone_invalidOtp_returns401() throws Exception {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(user.isPhoneVerified()).thenReturn(false);
        when(otpService.validate(anyString(), anyString())).thenReturn(false);

        String body = "{\"code\":\"000000\"}";
        mockMvc.perform(post("/api/v1/auth/verify-phone")
                        .with(csrf())
                        .principal(authFor(TEST_EMAIL))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Invalid or expired verification code"));
    }

    @Test
    @DisplayName("POST /auth/2fa/verify - invalid OTP returns 401 (was 200/success:false)")
    void twoFaVerify_invalidOtp_returns401() throws Exception {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(otpService.validate(anyString(), anyString())).thenReturn(false);

        String body = "{\"code\":\"000000\"}";
        mockMvc.perform(post("/api/v1/auth/2fa/verify")
                        .with(csrf())
                        .principal(authFor(TEST_EMAIL))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Invalid or expired verification code"));
    }

    @Test
    @DisplayName("POST /auth/2fa/verify-method - EMAIL_OTP wrong code returns 401 (was 200/success:false)")
    void twoFaVerifyMethod_invalidEmailOtp_returns401() throws Exception {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(otpService.validateWithResult(anyString(), anyString()))
                .thenReturn(com.fivucsas.identity.infrastructure.otp.OtpService.ValidationResult.invalid(2L));

        String body = "{\"method\":\"EMAIL_OTP\",\"data\":{\"code\":\"000000\"}}";
        mockMvc.perform(post("/api/v1/auth/2fa/verify-method")
                        .with(csrf())
                        .principal(authFor(TEST_EMAIL))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false));

        verify(auditLogPort, times(1)).logTwoFactorFailed(
                eq(userId.toString()), eq("EMAIL_OTP"), anyString(), anyString(), anyString());
        verify(auditLogPort, never()).logTwoFactorVerified(
                eq(userId.toString()), eq("EMAIL_OTP"), anyString(), anyString());
    }

    @Test
    @DisplayName("POST /auth/2fa/verify-method - QR_CODE invalid token returns 401")
    void twoFaVerifyMethod_invalidQrCode_returns401() throws Exception {
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));
        when(otpService.validate(anyString(), anyString())).thenReturn(false);

        String body = "{\"method\":\"QR_CODE\",\"data\":{\"token\":\"bogus\"}}";
        mockMvc.perform(post("/api/v1/auth/2fa/verify-method")
                        .with(csrf())
                        .principal(authFor(TEST_EMAIL))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("POST /auth/2fa/verify-method - empty method still 400 (input validation, not auth)")
    void twoFaVerifyMethod_emptyMethod_returns400() throws Exception {
        // This case is NOT changed by the P1 fix — empty `method` is a 400
        // (input validation) and the existing behaviour is preserved. Pinned
        // here so a future refactor doesn't accidentally collapse it into the
        // 401 branch.
        UUID userId = UUID.randomUUID();
        User user = userMock(userId);
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(user));

        String body = "{\"method\":\"\",\"data\":{}}";
        mockMvc.perform(post("/api/v1/auth/2fa/verify-method")
                        .with(csrf())
                        .principal(authFor(TEST_EMAIL))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }
}
