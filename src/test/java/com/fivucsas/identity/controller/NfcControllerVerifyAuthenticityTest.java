package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.application.service.ManageNfcCardService;
import com.fivucsas.identity.application.service.ManageNfcCardService.EnrollResult;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.entity.NfcCard;
import com.fivucsas.identity.infrastructure.adapter.BiometricProcessorClient;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
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

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link NfcController#verifyChipAuthenticity} and the passive-auth
 * gate on {@code /enroll} (WS2). The api treats the biometric-processor verdict
 * as authoritative and is FAIL-CLOSED: any error or non-authentic verdict
 * rejects the chip (422).
 */
@WebMvcTest(controllers = NfcController.class,
        excludeAutoConfiguration = {
                org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
                org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("NfcController NFC chip passive-authentication (WS2)")
class NfcControllerVerifyAuthenticityTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private ManageNfcCardService manageNfcCardService;
    @MockBean private BiometricProcessorClient biometricProcessorClient;
    @MockBean private BiometricServicePort biometricServicePort;
    @MockBean private AuditLogPort auditLogPort;

    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private RateLimitService rateLimitService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;

    private String json(Map<String, ?> m) throws Exception {
        return objectMapper.writeValueAsString(m);
    }

    // ------------------------------------------------------------------
    // /verify-authenticity
    // ------------------------------------------------------------------

    @Test
    @DisplayName("authentic chip → 200 authentic=true, audited NFC_CHIP_AUTHENTIC")
    void authenticChipReturns200() throws Exception {
        when(biometricServicePort.verifyNfcChipAuthenticity(eq("SODB64"), any()))
                .thenReturn(Map.of("is_authentic", true, "reason_code", "OK"));

        mockMvc.perform(post("/api/v1/nfc/verify-authenticity")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("sod", "SODB64", "dg1", "DG1B64"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.authentic").value(true));

        verify(auditLogPort).logSecurityEvent(any(), eq("NFC_CHIP_AUTHENTIC"), any(), anyString());
    }

    @Test
    @DisplayName("inauthentic chip → 422 fail-closed, audited NFC_CHIP_NOT_AUTHENTIC")
    void inauthenticChipReturns422() throws Exception {
        when(biometricServicePort.verifyNfcChipAuthenticity(anyString(), any()))
                .thenReturn(Map.of("is_authentic", false, "reason", "DS untrusted",
                        "reason_code", "DS_UNTRUSTED"));

        mockMvc.perform(post("/api/v1/nfc/verify-authenticity")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("sod", "SODB64"))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.authentic").value(false))
                .andExpect(jsonPath("$.errorCode").value("NFC_PA_NOT_AUTHENTIC"))
                .andExpect(jsonPath("$.reasonCode").value("DS_UNTRUSTED"));

        verify(auditLogPort).logSecurityEvent(any(), eq("NFC_CHIP_NOT_AUTHENTIC"), any(), anyString());
    }

    @Test
    @DisplayName("bio unavailable (success=false error map) → 422 fail-closed")
    void bioUnavailableFailsClosed() throws Exception {
        when(biometricServicePort.verifyNfcChipAuthenticity(anyString(), any()))
                .thenReturn(Map.of("success", false, "message", "NFC authenticity service unavailable"));

        mockMvc.perform(post("/api/v1/nfc/verify-authenticity")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("sod", "SODB64"))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.authentic").value(false));
    }

    @Test
    @DisplayName("missing SOD → 400 NFC_PA_MISSING_SOD, bio never called")
    void missingSodReturns400() throws Exception {
        mockMvc.perform(post("/api/v1/nfc/verify-authenticity")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("dg1", "DG1B64"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("NFC_PA_MISSING_SOD"));

        verify(biometricServicePort, never()).verifyNfcChipAuthenticity(any(), any());
    }

    // ------------------------------------------------------------------
    // /enroll passive-auth gate
    // ------------------------------------------------------------------

    @Test
    @DisplayName("enroll WITHOUT sod → no passive-auth call (legacy serial-only path unchanged)")
    void enrollWithoutSodSkipsPassiveAuth() throws Exception {
        UUID userId = UUID.randomUUID();
        NfcCard card = NfcCard.builder().id(UUID.randomUUID()).cardSerial("04A2245B").build();
        when(manageNfcCardService.enrollCard(any(), anyString(), anyString(), any(), anyBoolean(), any()))
                .thenReturn(new EnrollResult(EnrollResult.Status.OK, card, userId, false));

        mockMvc.perform(post("/api/v1/nfc/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("cardSerial", "04:a2:24:5b"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true));

        verify(biometricServicePort, never()).verifyNfcChipAuthenticity(any(), any());
    }

    @Test
    @DisplayName("enroll WITH sod + inauthentic chip → 422, card NOT enrolled")
    void enrollWithInauthenticChipRejected() throws Exception {
        when(biometricServicePort.verifyNfcChipAuthenticity(anyString(), any()))
                .thenReturn(Map.of("is_authentic", false, "reason", "SOD signature invalid",
                        "reason_code", "SIGNATURE_INVALID"));

        mockMvc.perform(post("/api/v1/nfc/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("cardSerial", "04A2245B", "sod", "SODB64", "dg1", "DG1"))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value("NFC_PA_NOT_AUTHENTIC"));

        verify(manageNfcCardService, never()).enrollCard(any(), any(), any(), any(), anyBoolean(), any());
    }

    @Test
    @DisplayName("enroll WITH sod + authentic chip → proceeds to enroll (201)")
    void enrollWithAuthenticChipProceeds() throws Exception {
        UUID userId = UUID.randomUUID();
        NfcCard card = NfcCard.builder().id(UUID.randomUUID()).cardSerial("04A2245B").build();
        when(biometricServicePort.verifyNfcChipAuthenticity(anyString(), any()))
                .thenReturn(Map.of("is_authentic", true));
        when(manageNfcCardService.enrollCard(any(), anyString(), anyString(), any(), anyBoolean(), any()))
                .thenReturn(new EnrollResult(EnrollResult.Status.OK, card, userId, false));

        mockMvc.perform(post("/api/v1/nfc/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("cardSerial", "04A2245B", "sod", "SODB64"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true));

        verify(manageNfcCardService).enrollCard(any(), eq("04A2245B"), anyString(), any(), anyBoolean(), any());
    }

    @Test
    @DisplayName("accepts bio-native 'sod_b64' field as well as 'sod'")
    void acceptsSodB64Field() throws Exception {
        when(biometricServicePort.verifyNfcChipAuthenticity(eq("SODB64"), any()))
                .thenReturn(Map.of("is_authentic", true));

        mockMvc.perform(post("/api/v1/nfc/verify-authenticity")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("sod_b64", "SODB64", "1", "DG1B64", "2", "DG2B64"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authentic").value(true));
    }
}
