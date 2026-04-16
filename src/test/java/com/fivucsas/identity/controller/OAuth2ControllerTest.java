package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.application.service.OAuth2Service;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = OAuth2Controller.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("OAuth2 Controller Tests")
class OAuth2ControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private OAuth2Service oAuth2Service;
    @MockBean private OAuth2ClientRepositoryPort oAuth2ClientRepository;
    @MockBean private MfaSessionRepository mfaSessionRepository;
    @MockBean private com.fivucsas.identity.domain.repository.UserRepository domainUserRepository;

    // Security and infrastructure beans
    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private RateLimitService rateLimitService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;
    @MockBean private OtpService otpService;
    @MockBean private EmailService emailService;
    @MockBean private SmsService smsService;

    @BeforeEach
    void allowRateLimiter() {
        // Rate-limit interceptor now covers /api/v1/oauth2/** — pass-through for tests.
        when(rateLimitService.allowLoginAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowRegistrationAttempt(anyString())).thenReturn(true);
        when(rateLimitService.allowBiometricVerification(anyString())).thenReturn(true);
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/authorize - Unsupported response_type")
    void authorize_WhenInvalidResponseType_ShouldReturn400() throws Exception {
        mockMvc.perform(get("/api/v1/oauth2/authorize")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("response_type", "token"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_response_type"));
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/authorize - Invalid client")
    void authorize_WhenInvalidClient_ShouldReturn400() throws Exception {
        when(oAuth2Service.validateClient("bad-client", "https://example.com/cb"))
                .thenThrow(new IllegalArgumentException("Invalid client_id: bad-client"));

        mockMvc.perform(get("/api/v1/oauth2/authorize")
                        .param("client_id", "bad-client")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("response_type", "code"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/authorize - Unauthenticated returns auth action")
    void authorize_WhenUnauthenticated_ShouldReturnAuthAction() throws Exception {
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.getClientName()).thenReturn("Test App");
        when(oAuth2Service.validateClient("test-client", "https://example.com/cb")).thenReturn(client);

        mockMvc.perform(get("/api/v1/oauth2/authorize")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("response_type", "code")
                        .param("state", "xyz"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.action").value("authenticate"))
                .andExpect(jsonPath("$.client_name").value("Test App"))
                .andExpect(jsonPath("$.state").value("xyz"));
    }

    @Test
    @DisplayName("POST /api/v1/oauth2/token - Unsupported grant_type")
    void token_WhenInvalidGrantType_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/v1/oauth2/token")
                        .param("grant_type", "client_credentials")
                        .param("code", "some-code")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("client_id", "test-client"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    @DisplayName("POST /api/v1/oauth2/token - Success")
    void token_WhenValidCode_ShouldReturnTokens() throws Exception {
        Map<String, Object> tokens = new LinkedHashMap<>();
        tokens.put("access_token", "jwt-token");
        tokens.put("token_type", "Bearer");
        tokens.put("expires_in", 3600L);
        tokens.put("id_token", "id-jwt");
        when(oAuth2Service.exchangeCode("valid-code", "test-client", "https://example.com/cb", null, null))
                .thenReturn(tokens);

        mockMvc.perform(post("/api/v1/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("code", "valid-code")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("client_id", "test-client"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("jwt-token"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.id_token").value("id-jwt"));
    }

    @Test
    @DisplayName("POST /api/v1/oauth2/token - With PKCE code_verifier")
    void token_WhenPkceCodeVerifier_ShouldPassToService() throws Exception {
        Map<String, Object> tokens = new LinkedHashMap<>();
        tokens.put("access_token", "jwt-token");
        tokens.put("token_type", "Bearer");
        tokens.put("expires_in", 3600L);
        tokens.put("id_token", "id-jwt");
        when(oAuth2Service.exchangeCode("valid-code", "test-client", "https://example.com/cb", null, "my-verifier"))
                .thenReturn(tokens);

        mockMvc.perform(post("/api/v1/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("code", "valid-code")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("client_id", "test-client")
                        .param("code_verifier", "my-verifier"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("jwt-token"));
    }

    @Test
    @DisplayName("POST /api/v1/oauth2/token - Invalid code")
    void token_WhenInvalidCode_ShouldReturn400() throws Exception {
        when(oAuth2Service.exchangeCode(anyString(), anyString(), anyString(), any(), any()))
                .thenThrow(new IllegalArgumentException("Invalid or expired authorization code"));

        mockMvc.perform(post("/api/v1/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("code", "bad-code")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("client_id", "test-client"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/userinfo - Missing bearer token")
    void userInfo_WhenNoToken_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/oauth2/userinfo"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/userinfo - Success")
    void userInfo_WhenValidToken_ShouldReturnClaims() throws Exception {
        Map<String, Object> claims = Map.of(
                "sub", "user-id-123",
                "email", "user@test.com",
                "name", "Test User");
        when(oAuth2Service.getUserInfo("valid-jwt")).thenReturn(claims);

        mockMvc.perform(get("/api/v1/oauth2/userinfo")
                        .header("Authorization", "Bearer valid-jwt"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("user-id-123"))
                .andExpect(jsonPath("$.email").value("user@test.com"));
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/userinfo - Invalid token")
    void userInfo_WhenInvalidToken_ShouldReturn401() throws Exception {
        when(oAuth2Service.getUserInfo("bad-jwt")).thenThrow(new RuntimeException("Token expired"));

        mockMvc.perform(get("/api/v1/oauth2/userinfo")
                        .header("Authorization", "Bearer bad-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/authorize - display=page issues 302 to hosted login")
    void authorize_WhenDisplayPage_ShouldRedirectToHostedLogin() throws Exception {
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.getClientName()).thenReturn("Test App");
        when(oAuth2Service.validateClient("test-client", "https://example.com/cb")).thenReturn(client);

        mockMvc.perform(get("/api/v1/oauth2/authorize")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("response_type", "code")
                        .param("state", "xyz")
                        .param("display", "page"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("verify.fivucsas.com/login")))
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("client_id=test-client")))
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("state=xyz")));
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/authorize - HTML Accept header also redirects")
    void authorize_WhenAcceptHtml_ShouldRedirectToHostedLogin() throws Exception {
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.getClientName()).thenReturn("Test App");
        when(oAuth2Service.validateClient("test-client", "https://example.com/cb")).thenReturn(client);

        mockMvc.perform(get("/api/v1/oauth2/authorize")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("response_type", "code")
                        .header("Accept", "text/html,application/xhtml+xml"))
                .andExpect(status().isFound());
    }

    @Test
    @DisplayName("GET /api/v1/oauth2/clients/{id}/public - unknown client returns 404")
    void getClientPublicMeta_WhenUnknown_ShouldReturn404() throws Exception {
        when(oAuth2ClientRepository.findByClientIdAndActiveTrue("ghost"))
                .thenReturn(java.util.Optional.empty());

        mockMvc.perform(get("/api/v1/oauth2/clients/ghost/public"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("not_found"));
    }

    @Test
    @DisplayName("POST /api/v1/oauth2/authorize/complete - missing fields return 400")
    void authorizeComplete_WhenMissingFields_ShouldReturn400() throws Exception {
        mockMvc.perform(post("/api/v1/oauth2/authorize/complete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }
}
