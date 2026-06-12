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

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
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
    @MockBean private com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy clientSideEmbeddingPolicy;
    @MockBean private com.fivucsas.identity.application.service.ClientSideVoiceEmbeddingPolicy clientSideVoiceEmbeddingPolicy;

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

    // Fingerprint enroll/verify tests removed (P1.4): the underlying endpoints
    // were a SHA-256 hash placeholder, not a real biometric. Platform fingerprint
    // is now WebAuthn-only — see WebAuthnControllerTest / FingerprintAuthHandlerTest.

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

    // P1.4: enrollFingerprint success test removed alongside the endpoint.

    /**
     * USER-BUG-4 regression: face-search must scope by the authenticated user's
     * tenant_id (derived server-side), not by an unrelated request param. The bug
     * fixed here was that the controller used to forward whatever (or nothing)
     * the client sent for `tenant_id`, causing searches to be scoped to NULL and
     * silently miss real enrollments. After the fix, the tenant_id supplied to
     * the downstream BiometricServicePort.searchFace must be the principal's
     * own tenant — even if the caller tries to override it via the form param.
     */
    @Test
    @DisplayName("POST /api/v1/biometric/search - Tenant scope is derived from authenticated user (USER-BUG-4)")
    void searchFace_ShouldScopeByCurrentUserTenant() throws Exception {
        UUID tenantUuid = UUID.fromString("11111111-1111-1111-1111-111111111111");

        // Stub the security-layer helper that the controller now depends on for
        // tenant resolution. Returning the principal's tenant id directly avoids
        // touching `entity.User` from this test (mirrors the production path
        // where the JPA entity stays inside `security..` per the hexagonal
        // boundary enforced by UserDomainBoundaryTest).
        when(rbacService.getCurrentUserTenantId()).thenReturn(Optional.of(tenantUuid));
        when(biometricServicePort.searchFace(any(), eq(tenantUuid.toString()), any(), any()))
                .thenReturn(Map.of("found", true, "matches", java.util.List.of()));

        MockMultipartFile image = new MockMultipartFile(
                "file", "face.jpg", MediaType.IMAGE_JPEG_VALUE, "fake-image-bytes".getBytes());

        mockMvc.perform(multipart("/api/v1/biometric/search")
                        .file(image)
                        // Hostile attempt to override scope: client sends a different tenant.
                        // The controller MUST ignore this and use the principal's tenant.
                        .param("tenant_id", "00000000-0000-0000-0000-000000000000"))
                .andExpect(status().isOk());

        // Verify the downstream port was invoked with the principal's tenant,
        // NOT the client-supplied form value.
        verify(biometricServicePort).searchFace(any(), eq(tenantUuid.toString()), any(), any());
    }

    // --- Phase 6: JSON client-side-embedding enroll endpoint ---
    // POST /api/v1/biometric/enroll-embedding/{userId} { embedding: number[512], tenant_id? }
    // (NOTE: this controller slice runs with addFilters=false, so @PreAuthorize is
    // NOT enforced here — the authorization gate is pinned separately + deterministically
    // by BiometricControllerSecurityTest. These tests cover routing/validation/flag-gating.)

    private static String embeddingJson(int length, String tenantId) {
        StringBuilder sb = new StringBuilder("{\"embedding\":[");
        for (int i = 0; i < length; i++) {
            if (i > 0) sb.append(',');
            sb.append("0.01");
        }
        sb.append(']');
        if (tenantId != null) {
            sb.append(",\"tenant_id\":\"").append(tenantId).append('\"');
        }
        sb.append('}');
        return sb.toString();
    }

    @Test
    @DisplayName("POST enroll-embedding - flag ON + valid 512-vector → routes to use case (success)")
    void enrollEmbedding_flagOn_validVector_succeeds() throws Exception {
        UUID userId = UUID.randomUUID();
        String tenantId = "11111111-1111-1111-1111-111111111111";

        when(clientSideEmbeddingPolicy.isEnabledForTenant(tenantId)).thenReturn(true);
        when(enrollBiometricUseCase.execute(any()))
                .thenReturn(com.fivucsas.identity.application.dto.response.BiometricResponse.builder()
                        .success(true)
                        .message("Embedding enrolled")
                        .userId(userId.toString())
                        .build());

        mockMvc.perform(post("/api/v1/biometric/enroll-embedding/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(embeddingJson(512, tenantId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verified").value(true))
                .andExpect(jsonPath("$.message").value("Embedding enrolled"));

        // The command carried the embedding (not an image) and the resolved tenant.
        org.mockito.ArgumentCaptor<com.fivucsas.identity.application.dto.command.EnrollBiometricCommand> cmd =
                org.mockito.ArgumentCaptor.forClass(
                        com.fivucsas.identity.application.dto.command.EnrollBiometricCommand.class);
        verify(enrollBiometricUseCase).execute(cmd.capture());
        org.assertj.core.api.Assertions.assertThat(cmd.getValue().getEmbedding()).hasSize(512);
        org.assertj.core.api.Assertions.assertThat(cmd.getValue().getTenantId()).isEqualTo(tenantId);
        org.assertj.core.api.Assertions.assertThat(cmd.getValue().getFaceImage()).isNull();
        org.assertj.core.api.Assertions.assertThat(cmd.getValue().getUserId()).isEqualTo(userId.toString());
    }

    @Test
    @DisplayName("POST enroll-embedding - flag ON + tenant_id omitted → tenant derived from principal")
    void enrollEmbedding_flagOn_noTenant_derivesFromPrincipal() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID tenantUuid = UUID.fromString("22222222-2222-2222-2222-222222222222");

        when(rbacService.getCurrentUserTenantId()).thenReturn(Optional.of(tenantUuid));
        when(clientSideEmbeddingPolicy.isEnabledForTenant(tenantUuid.toString())).thenReturn(true);
        when(enrollBiometricUseCase.execute(any()))
                .thenReturn(com.fivucsas.identity.application.dto.response.BiometricResponse.builder()
                        .success(true).message("ok").userId(userId.toString()).build());

        mockMvc.perform(post("/api/v1/biometric/enroll-embedding/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(embeddingJson(512, null)))
                .andExpect(status().isOk());

        org.mockito.ArgumentCaptor<com.fivucsas.identity.application.dto.command.EnrollBiometricCommand> cmd =
                org.mockito.ArgumentCaptor.forClass(
                        com.fivucsas.identity.application.dto.command.EnrollBiometricCommand.class);
        verify(enrollBiometricUseCase).execute(cmd.capture());
        org.assertj.core.api.Assertions.assertThat(cmd.getValue().getTenantId()).isEqualTo(tenantUuid.toString());
    }

    @Test
    @DisplayName("POST enroll-embedding - flag OFF → 403, use case NEVER invoked (fail-closed)")
    void enrollEmbedding_flagOff_rejected() throws Exception {
        UUID userId = UUID.randomUUID();
        String tenantId = "11111111-1111-1111-1111-111111111111";

        when(clientSideEmbeddingPolicy.isEnabledForTenant(tenantId)).thenReturn(false);

        mockMvc.perform(post("/api/v1/biometric/enroll-embedding/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(embeddingJson(512, tenantId)))
                .andExpect(status().isForbidden());

        // Fail-closed: nothing was enrolled — the embedding path is gated entirely.
        verify(enrollBiometricUseCase, org.mockito.Mockito.never()).execute(any());
    }

    @Test
    @DisplayName("POST enroll-embedding - wrong-length vector (511) → 400, use case NEVER invoked")
    void enrollEmbedding_wrongLength_badRequest() throws Exception {
        UUID userId = UUID.randomUUID();
        String tenantId = "11111111-1111-1111-1111-111111111111";

        mockMvc.perform(post("/api/v1/biometric/enroll-embedding/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(embeddingJson(511, tenantId)))
                .andExpect(status().isBadRequest());

        verify(enrollBiometricUseCase, org.mockito.Mockito.never()).execute(any());
    }

    @Test
    @DisplayName("POST enroll-embedding - empty vector → 400, use case NEVER invoked")
    void enrollEmbedding_emptyVector_badRequest() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/biometric/enroll-embedding/" + userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"embedding\":[]}"))
                .andExpect(status().isBadRequest());

        verify(enrollBiometricUseCase, org.mockito.Mockito.never()).execute(any());
    }
}
