package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.CachePort;
import com.fivucsas.identity.application.service.ManageNfcCardService;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.infrastructure.adapter.BiometricProcessorClient;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtAuthenticationFilter;
import com.fivucsas.identity.security.RateLimitService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link NfcController#verifyMrz} (T2-A, INVESTIGATION 2026-05-07 P1).
 *
 * <p>Covers the three scenarios called out in the task spec:</p>
 * <ol>
 *     <li>Happy path — valid MRZ, bio reports checksum_valid=true, controller
 *         returns 200 with masked document number and writes an audit row.</li>
 *     <li>Invalid checksum — bio reports checksum_valid=false, controller
 *         returns 400 with errorCode=NFC_MRZ_CHECKSUM_FAILED and forwards
 *         the failing field names.</li>
 *     <li>Bio unreachable — BiometricProcessorClient surfaces
 *         {success=false, error="Biometric processor unavailable"} and the
 *         controller returns 502 with errorCode=NFC_MRZ_BIO_UNAVAILABLE.</li>
 * </ol>
 *
 * <p>Plus input-contract coverage (missing input, ambiguous input, bio
 * rejected = 400) and the masking helper.</p>
 */
@WebMvcTest(controllers = NfcController.class,
        excludeAutoConfiguration = {
                org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
                org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration.class
        })
@ActiveProfiles("test")
@AutoConfigureMockMvc(addFilters = false)
@DisplayName("NfcController.verifyMrz tests")
class NfcControllerVerifyMrzTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private ManageNfcCardService manageNfcCardService;
    @MockBean private BiometricProcessorClient biometricProcessorClient;
    @MockBean private AuditLogPort auditLogPort;

    // Spring-Security / infra beans the WebMvcTest slice still demands
    @MockBean private TenantRepository tenantRepository;
    @MockBean private UserRepository userRepository;
    @MockBean private JwtAuthenticationFilter jwtAuthenticationFilter;
    @MockBean private UserDetailsService userDetailsService;
    @MockBean private RateLimitService rateLimitService;
    @MockBean private PasswordEncoder passwordEncoder;
    @MockBean private CachePort cachePort;
    @MockBean private RedisConnectionFactory redisConnectionFactory;
    @MockBean private StringRedisTemplate stringRedisTemplate;

    private static final String SAMPLE_MRZ =
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n"
                    + "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    // ------------------------------------------------------------------
    // Happy path
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Happy path: valid MRZ returns 200 with masked document number")
    void verifyMrz_validInput_returns200_andWritesAuditLog() throws Exception {
        Map<String, Object> bioResponse = bioOk(true);
        when(biometricProcessorClient.verifyMrz(eq(SAMPLE_MRZ), eq(null)))
                .thenReturn(bioResponse);

        mockMvc.perform(post("/api/v1/nfc/verify-mrz")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("mrzText", SAMPLE_MRZ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.checksumValid").value(true))
                // Full document_number ("L898902C3") must be masked in the response —
                // only last 4 chars are surfaced.
                .andExpect(jsonPath("$.documentNumberMasked").value("*****02C3"))
                .andExpect(jsonPath("$.issuingCountry").value("UTO"))
                .andExpect(jsonPath("$.surname").value("ERIKSSON"))
                .andExpect(jsonPath("$.mrzFormat").value("TD3"));

        // Audit row should fire with success=true and the masked doc number.
        verify(auditLogPort).logNfcDocumentVerified(
                any(),                  // userId (no auth context in addFilters=false)
                eq("*****02C3"),        // masked doc number
                eq("UTO"),
                eq("TD3"),
                eq(true),
                any(), any()
        );
    }

    // ------------------------------------------------------------------
    // Invalid checksum
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Invalid checksum: bio reports checksum_valid=false → 400 NFC_MRZ_CHECKSUM_FAILED")
    void verifyMrz_checksumFails_returns400() throws Exception {
        Map<String, Object> bioResponse = bioOk(false);
        bioResponse.put("checksum_failures", List.of("document_number", "composite"));
        when(biometricProcessorClient.verifyMrz(eq(SAMPLE_MRZ), eq(null)))
                .thenReturn(bioResponse);

        mockMvc.perform(post("/api/v1/nfc/verify-mrz")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("mrzText", SAMPLE_MRZ))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.errorCode").value("NFC_MRZ_CHECKSUM_FAILED"))
                .andExpect(jsonPath("$.checksumFailures[0]").value("document_number"))
                .andExpect(jsonPath("$.checksumFailures[1]").value("composite"));

        // Even on checksum failure we still audit the attempt — that's how
        // SOC detects guessing campaigns.
        ArgumentCaptor<Boolean> validCaptor = ArgumentCaptor.forClass(Boolean.class);
        verify(auditLogPort).logNfcDocumentVerified(
                any(), any(), any(), any(), validCaptor.capture(), any(), any());
        assertThat(validCaptor.getValue()).isFalse();
    }

    // ------------------------------------------------------------------
    // Bio unreachable
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Bio unreachable: client returns success=false → 502 NFC_MRZ_BIO_UNAVAILABLE")
    void verifyMrz_bioUnreachable_returns502() throws Exception {
        when(biometricProcessorClient.verifyMrz(eq(SAMPLE_MRZ), eq(null)))
                .thenReturn(Map.of(
                        "success", false,
                        "error", "Biometric processor unavailable"
                ));

        mockMvc.perform(post("/api/v1/nfc/verify-mrz")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("mrzText", SAMPLE_MRZ))))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.errorCode").value("NFC_MRZ_BIO_UNAVAILABLE"));

        // Transport-layer failures should NOT write an audit row — there's
        // no document context to record. Document-level events only.
        verify(auditLogPort, never()).logNfcDocumentVerified(
                any(), any(), any(), any(), anyBoolean(), any(), any());
    }

    @Test
    @DisplayName("Bio rejected (4xx): surfaces as 400 NFC_MRZ_PARSE_FAILED")
    void verifyMrz_bioRejected_returns400() throws Exception {
        when(biometricProcessorClient.verifyMrz(eq("garbage"), eq(null)))
                .thenReturn(Map.of(
                        "success", false,
                        "error", "Biometric processor rejected request: Could not parse MRZ"
                ));

        mockMvc.perform(post("/api/v1/nfc/verify-mrz")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("mrzText", "garbage"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("NFC_MRZ_PARSE_FAILED"));
    }

    // ------------------------------------------------------------------
    // Input contract
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Missing both inputs: 400 NFC_MRZ_MISSING_INPUT")
    void verifyMrz_missingInput_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/nfc/verify-mrz")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("NFC_MRZ_MISSING_INPUT"));

        verify(biometricProcessorClient, never()).verifyMrz(any(), any());
    }

    @Test
    @DisplayName("Both inputs supplied: 400 NFC_MRZ_AMBIGUOUS_INPUT")
    void verifyMrz_bothInputs_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/nfc/verify-mrz")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "mrzText", SAMPLE_MRZ,
                                "dg1BytesB64", "AAAA"
                        ))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("NFC_MRZ_AMBIGUOUS_INPUT"));

        verify(biometricProcessorClient, never()).verifyMrz(any(), any());
    }

    // ------------------------------------------------------------------
    // Masking helper
    // ------------------------------------------------------------------

    @Test
    @DisplayName("maskDocumentNumber: standard, short and null inputs")
    void maskDocumentNumber_inputs() {
        assertThat(NfcController.maskDocumentNumber("L898902C3")).isEqualTo("*****02C3");
        assertThat(NfcController.maskDocumentNumber("ABCD")).isEqualTo("****");
        assertThat(NfcController.maskDocumentNumber("AB")).isEqualTo("****");
        assertThat(NfcController.maskDocumentNumber("")).isEqualTo("");
        assertThat(NfcController.maskDocumentNumber(null)).isNull();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Build a canonical bio success response — caller flips checksum_valid. */
    private static Map<String, Object> bioOk(boolean checksumValid) {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("document_type", "P");
        resp.put("issuing_country", "UTO");
        resp.put("surname", "ERIKSSON");
        resp.put("given_names", "ANNA MARIA");
        resp.put("document_number", "L898902C3");
        resp.put("nationality", "UTO");
        resp.put("date_of_birth", "1974-08-12");
        resp.put("sex", "F");
        resp.put("date_of_expiry", "2012-04-15");
        resp.put("personal_number", "ZE184226B");
        resp.put("checksum_valid", checksumValid);
        resp.put("checksum_failures", List.of());
        resp.put("mrz_format", "TD3");
        return resp;
    }
}
