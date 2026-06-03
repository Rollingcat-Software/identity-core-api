package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.dto.response.EnrollmentResponse;
import com.fivucsas.identity.application.port.input.EnrollBiometricUseCase;
import com.fivucsas.identity.application.port.input.ManageEnrollmentUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.application.service.EnrollmentHealthService;
import com.fivucsas.identity.application.service.EnrollmentQueryService;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.domain.model.auth.EnrollmentStatus;
import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.entity.UserEnrollment;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.repository.UserEnrollmentRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = EnrollmentController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("Enrollment Controller Tests")
class EnrollmentControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private EnrollmentQueryService enrollmentQueryService;
    @MockBean private UserEnrollmentRepository enrollmentRepository;
    @MockBean private ManageEnrollmentUseCase manageEnrollmentUseCase;
    @MockBean private EnrollBiometricUseCase enrollBiometricUseCase;
    @MockBean private BiometricServicePort biometricService;
    @MockBean private RbacAuthorizationService rbacService;
    @MockBean private EnrollmentHealthService enrollmentHealthService;
    @MockBean private TenantScopeResolver tenantScopeResolver;

    // Security and infrastructure beans
    @MockBean private TenantRepository tenantRepository;
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
    @DisplayName("GET /api/v1/enrollments - Success")
    void getAllEnrollments_ShouldReturnList() throws Exception {
        EnrollmentDto dto = EnrollmentDto.builder()
                .id(UUID.randomUUID().toString())
                .userId(UUID.randomUUID().toString())
                .authMethodType("PASSWORD")
                .status("ENROLLED")
                .build();
        // Controller now calls getAllEnrollments(tenantScopeId) with null when
        // the caller is ROOT (resolver returns null). Match any UUID.
        when(enrollmentQueryService.getAllEnrollments(org.mockito.ArgumentMatchers.<java.util.UUID>any()))
                .thenReturn(List.of(dto));

        mockMvc.perform(get("/api/v1/enrollments"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].authMethodType").value("PASSWORD"));
    }

    @Test
    @DisplayName("GET /api/v1/enrollments/{id} - Success")
    void getEnrollmentById_ShouldReturnEnrollment() throws Exception {
        UUID id = UUID.randomUUID();
        EnrollmentDto dto = EnrollmentDto.builder()
                .id(id.toString())
                .authMethodType("FACE")
                .status("ENROLLED")
                .build();
        when(enrollmentQueryService.getEnrollmentById(id)).thenReturn(dto);

        mockMvc.perform(get("/api/v1/enrollments/" + id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authMethodType").value("FACE"));
    }

    @Test
    @DisplayName("DELETE /api/v1/enrollments/{id} - Success (204)")
    void deleteEnrollment_ShouldReturnNoContent() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(delete("/api/v1/enrollments/" + id))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("GET /api/v1/users/{userId}/enrollments - Success")
    void getUserEnrollments_ShouldReturnList() throws Exception {
        UUID userId = UUID.randomUUID();
        EnrollmentResponse response = new EnrollmentResponse(
                UUID.randomUUID(), AuthMethodType.TOTP, EnrollmentStatus.ENROLLED,
                Instant.now(), null, Instant.now(), userId.toString(), "Test", "test@test.com",
                UUID.randomUUID().toString(), null, null, null, null, null);
        when(manageEnrollmentUseCase.getUserEnrollments(userId)).thenReturn(List.of(response));

        mockMvc.perform(get("/api/v1/users/" + userId + "/enrollments"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    @DisplayName("POST /api/v1/users/{userId}/enrollments - Success (201)")
    void startEnrollment_ShouldReturnCreated() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        EnrollmentResponse response = new EnrollmentResponse(
                UUID.randomUUID(), AuthMethodType.PASSWORD, EnrollmentStatus.ENROLLED,
                Instant.now(), null, Instant.now(), userId.toString(), "Test", "test@test.com",
                tenantId.toString(), null, null, null, null, null);
        when(manageEnrollmentUseCase.startEnrollment(eq(userId), eq(tenantId), eq(AuthMethodType.PASSWORD)))
                .thenReturn(response);

        mockMvc.perform(post("/api/v1/users/" + userId + "/enrollments")
                        .param("tenantId", tenantId.toString())
                        .param("methodType", "PASSWORD"))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("DELETE /api/v1/users/{userId}/enrollments/{methodType} - Success (204)")
    void revokeEnrollment_ShouldReturnNoContent() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(delete("/api/v1/users/" + userId + "/enrollments/FACE"))
                .andExpect(status().isNoContent());
    }
}
