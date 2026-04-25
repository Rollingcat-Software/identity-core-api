package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.StepUpAuthUseCase;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = BiometricController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("Biometric Controller Tests")
class BiometricControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private EnrollBiometricUseCase enrollBiometricUseCase;
    @MockBean private VerifyBiometricUseCase verifyBiometricUseCase;
    @MockBean private BiometricServicePort biometricServicePort;
    @MockBean private StepUpAuthUseCase stepUpAuthUseCase;
    @MockBean private com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase manageEnrollmentUseCase;
    @MockBean private RbacAuthorizationService rbacService;

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

    @Test
    @DisplayName("GET /api/v1/biometric/health - Success")
    void biometricHealth_WhenHealthy_ShouldReturnOk() throws Exception {
        when(biometricServicePort.checkHealth())
                .thenReturn(Map.of("status", "healthy", "version", "1.0"));

        mockMvc.perform(get("/api/v1/biometric/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("healthy"));
    }

    @Test
    @DisplayName("GET /api/v1/biometric/health - Service unavailable")
    void biometricHealth_WhenUnhealthy_ShouldReturn503() throws Exception {
        when(biometricServicePort.checkHealth()).thenThrow(new RuntimeException("Connection refused"));

        mockMvc.perform(get("/api/v1/biometric/health"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("unhealthy"));
    }

    @Test
    @DisplayName("POST /api/v1/biometric/fingerprint/enroll/{userId} - Missing data")
    void enrollFingerprint_WhenMissingData_ShouldReturnBadRequest() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/biometric/fingerprint/enroll/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fingerprintData\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.verified").value(false))
                .andExpect(jsonPath("$.message").value("fingerprintData is required"));
    }

    @Test
    @DisplayName("POST /api/v1/biometric/fingerprint/verify/{userId} - Missing data")
    void verifyFingerprint_WhenMissingData_ShouldReturnBadRequest() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/biometric/fingerprint/verify/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fingerprintData\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.verified").value(false))
                .andExpect(jsonPath("$.message").value("fingerprintData is required"));
    }

    @Test
    @DisplayName("POST /api/v1/biometric/voice/enroll/{userId} - Missing data")
    void enrollVoice_WhenMissingData_ShouldReturnBadRequest() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/biometric/voice/enroll/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"voiceData\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.verified").value(false))
                .andExpect(jsonPath("$.message").value("voiceData is required"));
    }

    @Test
    @DisplayName("POST /api/v1/biometric/voice/verify/{userId} - Missing data")
    void verifyVoice_WhenMissingData_ShouldReturnBadRequest() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/biometric/voice/verify/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"voiceData\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.verified").value(false))
                .andExpect(jsonPath("$.message").value("voiceData is required"));
    }

    @Test
    @DisplayName("DELETE /api/v1/biometric/face/{userId} - Success")
    void deleteFace_WhenSuccess_ShouldReturnOk() throws Exception {
        UUID userId = UUID.randomUUID();
        when(biometricServicePort.deleteFace(userId))
                .thenReturn(Map.of("success", true));

        mockMvc.perform(delete("/api/v1/biometric/face/" + userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true))
                .andExpect(jsonPath("$.message").value("Face data deleted successfully"));
    }

    @Test
    @DisplayName("POST /api/v1/biometric/voice/search - Missing voiceData")
    void searchVoice_WhenMissingData_ShouldReturnBadRequest() throws Exception {
        mockMvc.perform(post("/api/v1/biometric/voice/search")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"voiceData\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("voiceData is required"));
    }

    @Test
    @DisplayName("POST /api/v1/biometric/fingerprint/enroll/{userId} - Success")
    void enrollFingerprint_WhenValid_ShouldReturnSuccess() throws Exception {
        UUID userId = UUID.randomUUID();
        when(biometricServicePort.enrollFingerprint(any(UUID.class), any(String.class)))
                .thenReturn(Map.of("success", true));

        mockMvc.perform(post("/api/v1/biometric/fingerprint/enroll/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fingerprintData\":\"base64encodeddata\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true))
                .andExpect(jsonPath("$.message").value("Fingerprint enrolled successfully"));
    }
}
