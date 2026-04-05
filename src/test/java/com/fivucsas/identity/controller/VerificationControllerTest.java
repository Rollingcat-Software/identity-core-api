package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.dto.command.CreateVerificationSessionCommand;
import com.fivucsas.identity.application.dto.command.ReviewVerificationStepCommand;
import com.fivucsas.identity.application.dto.command.SubmitVerificationStepCommand;
import com.fivucsas.identity.application.dto.response.IndustryTemplateResponse;
import com.fivucsas.identity.application.dto.response.VerificationSessionResponse;
import com.fivucsas.identity.application.dto.response.VerificationStatusResponse;
import com.fivucsas.identity.application.dto.response.VerificationStepResultResponse;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.application.service.ManageVerificationService;
import com.fivucsas.identity.domain.model.auth.VerificationLevel;
import com.fivucsas.identity.domain.model.auth.VerificationSessionStatus;
import com.fivucsas.identity.domain.model.auth.VerificationStepStatus;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import jakarta.persistence.EntityNotFoundException;
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

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = VerificationController.class,
        excludeAutoConfiguration = {
            org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
            org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("Verification Controller Tests")
class VerificationControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private ManageVerificationService verificationService;

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

    private final UUID sessionId = UUID.randomUUID();
    private final UUID userId = UUID.randomUUID();
    private final UUID tenantId = UUID.randomUUID();
    private final UUID flowId = UUID.randomUUID();

    @Test
    @DisplayName("POST /api/v1/verification/sessions - Success (201)")
    void createSession_ShouldReturnCreated() throws Exception {
        VerificationSessionResponse response = new VerificationSessionResponse(
                sessionId, userId, tenantId, flowId, "KYC Flow",
                VerificationSessionStatus.PENDING, 0,
                null, null, Instant.now().plusSeconds(1800),
                List.of(), Instant.now(), Instant.now());
        when(verificationService.createSession(userId, tenantId, flowId)).thenReturn(response);

        CreateVerificationSessionCommand command = new CreateVerificationSessionCommand(userId, tenantId, flowId);

        mockMvc.perform(post("/api/v1/verification/sessions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(sessionId.toString()))
                .andExpect(jsonPath("$.status").value("PENDING"));
    }

    @Test
    @DisplayName("GET /api/v1/verification/sessions/{id} - Success")
    void getSession_ShouldReturnSession() throws Exception {
        VerificationSessionResponse response = new VerificationSessionResponse(
                sessionId, userId, tenantId, flowId, "KYC Flow",
                VerificationSessionStatus.IN_PROGRESS, 1,
                Instant.now(), null, Instant.now().plusSeconds(1800),
                List.of(), Instant.now(), Instant.now());
        when(verificationService.getSession(sessionId)).thenReturn(response);

        mockMvc.perform(get("/api/v1/verification/sessions/" + sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"));
    }

    @Test
    @DisplayName("GET /api/v1/verification/templates - Returns templates")
    void getTemplates_ShouldReturnList() throws Exception {
        List<IndustryTemplateResponse> templates = List.of(
                new IndustryTemplateResponse("FINTECH_KYC", "Fintech KYC", "desc",
                        List.of("DOCUMENT_SCAN", "FACE_MATCH")));
        when(verificationService.getTemplates()).thenReturn(templates);

        mockMvc.perform(get("/api/v1/verification/templates"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].templateId").value("FINTECH_KYC"));
    }

    @Test
    @DisplayName("POST /api/v1/verification/sessions/{id}/steps/{stepNumber} - Success")
    void submitStepResult_ShouldReturnResult() throws Exception {
        VerificationStepResultResponse stepResponse = new VerificationStepResultResponse(
                UUID.randomUUID(), 1, "DOCUMENT_SCAN", VerificationStepStatus.COMPLETED,
                0.95, "{}", null, Instant.now(), Instant.now());
        when(verificationService.submitStepResult(eq(sessionId), eq(1), any(SubmitVerificationStepCommand.class)))
                .thenReturn(stepResponse);

        SubmitVerificationStepCommand command = new SubmitVerificationStepCommand(
                "DOCUMENT_SCAN", 0.95, "{}", null);

        mockMvc.perform(post("/api/v1/verification/sessions/" + sessionId + "/steps/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.stepType").value("DOCUMENT_SCAN"))
                .andExpect(jsonPath("$.status").value("COMPLETED"));
    }

    @Test
    @DisplayName("POST /api/v1/verification/sessions/{id}/complete - Success")
    void completeSession_ShouldReturnCompleted() throws Exception {
        VerificationSessionResponse response = new VerificationSessionResponse(
                sessionId, userId, tenantId, flowId, "KYC Flow",
                VerificationSessionStatus.COMPLETED, 3,
                Instant.now(), Instant.now(), Instant.now().plusSeconds(1800),
                List.of(), Instant.now(), Instant.now());
        when(verificationService.completeSession(sessionId)).thenReturn(response);

        mockMvc.perform(post("/api/v1/verification/sessions/" + sessionId + "/complete"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMPLETED"));
    }

    @Test
    @DisplayName("GET /api/v1/verification/results/{userId} - Success")
    void getUserVerificationStatus_ShouldReturnStatus() throws Exception {
        VerificationStatusResponse statusResponse = new VerificationStatusResponse(
                userId, true, VerificationLevel.STANDARD, Instant.now(), List.of());
        when(verificationService.getUserVerificationStatus(userId)).thenReturn(statusResponse);

        mockMvc.perform(get("/api/v1/verification/results/" + userId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.identityVerified").value(true))
                .andExpect(jsonPath("$.verificationLevel").value("STANDARD"));
    }

    @Test
    @DisplayName("POST /api/v1/verification/sessions/{id}/steps/{stepNumber}/review - Success")
    void reviewStep_ShouldReturnResult() throws Exception {
        VerificationStepResultResponse stepResponse = new VerificationStepResultResponse(
                UUID.randomUUID(), 1, "VIDEO_INTERVIEW", VerificationStepStatus.COMPLETED,
                null, "{\"review_approved\":true}", null, Instant.now(), Instant.now());
        when(verificationService.reviewStep(eq(sessionId), eq(1), eq(true), eq("Approved")))
                .thenReturn(stepResponse);

        ReviewVerificationStepCommand command = new ReviewVerificationStepCommand(true, "Approved");

        mockMvc.perform(post("/api/v1/verification/sessions/" + sessionId + "/steps/1/review")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(command)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMPLETED"));
    }
}
