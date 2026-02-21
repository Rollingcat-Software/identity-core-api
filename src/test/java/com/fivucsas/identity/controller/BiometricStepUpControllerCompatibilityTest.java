package com.fivucsas.identity.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.dto.BiometricChallengeResponse;
import com.fivucsas.identity.dto.BiometricRegisterDeviceRequest;
import com.fivucsas.identity.dto.BiometricStepUpTokenResponse;
import com.fivucsas.identity.dto.BiometricVerifyChallengeRequest;
import com.fivucsas.identity.service.BiometricStepUpService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = {
        AuthBiometricStepUpController.class,
        LegacyBiometricStepUpController.class
})
@Import(BiometricStepUpControllerCompatibilityTest.TestSecurityConfig.class)
@DisplayName("Biometric Step-Up Endpoint Compatibility Tests")
class BiometricStepUpControllerCompatibilityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private BiometricStepUpService biometricStepUpService;

    @TestConfiguration
    static class TestSecurityConfig {
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                    .csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                    .httpBasic(Customizer.withDefaults());
            return http.build();
        }
    }

    @Test
    @DisplayName("Should register device on primary path")
    void shouldRegisterDeviceOnPrimaryPath() throws Exception {
        BiometricRegisterDeviceRequest request = validRegisterRequest();
        when(biometricStepUpService.registerDevice(eq("tester@fivucsas.local"), any(BiometricRegisterDeviceRequest.class)))
                .thenReturn("device-123");

        mockMvc.perform(post("/api/v1/auth/biometric/devices")
                        .with(user("tester@fivucsas.local"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deviceId").value("device-123"));

        verify(biometricStepUpService).registerDevice(eq("tester@fivucsas.local"), any(BiometricRegisterDeviceRequest.class));
    }

    @Test
    @DisplayName("Should register device on legacy path")
    void shouldRegisterDeviceOnLegacyPath() throws Exception {
        BiometricRegisterDeviceRequest request = validRegisterRequest();
        when(biometricStepUpService.registerDevice(eq("tester@fivucsas.local"), any(BiometricRegisterDeviceRequest.class)))
                .thenReturn("legacy-device-123");

        mockMvc.perform(post("/api/v1/step-up/register-device")
                        .with(user("tester@fivucsas.local"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deviceId").value("legacy-device-123"));

        verify(biometricStepUpService).registerDevice(eq("tester@fivucsas.local"), any(BiometricRegisterDeviceRequest.class));
    }

    @Test
    @DisplayName("Should create challenge on both primary and legacy paths")
    void shouldCreateChallengeOnBothPaths() throws Exception {
        BiometricChallengeResponse response = BiometricChallengeResponse.builder()
                .challengeId("challenge-1")
                .nonceBase64("nonce-value")
                .expiresAt(Instant.parse("2026-02-20T17:00:00Z"))
                .build();

        when(biometricStepUpService.createChallenge("tester@fivucsas.local")).thenReturn(response);

        mockMvc.perform(post("/api/v1/auth/biometric/challenge")
                        .with(user("tester@fivucsas.local")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("challenge-1"));

        mockMvc.perform(post("/api/v1/step-up/challenge")
                        .with(user("tester@fivucsas.local")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("challenge-1"));

        verify(biometricStepUpService).createChallenge("tester@fivucsas.local");
    }

    @Test
    @DisplayName("Should verify challenge on legacy path")
    void shouldVerifyChallengeOnLegacyPath() throws Exception {
        BiometricVerifyChallengeRequest request = new BiometricVerifyChallengeRequest();
        request.setChallengeId("2d7af6de-3c06-431c-bd9e-20d0c5f44f39");
        request.setKeyId("key-123");
        request.setSignatureBase64("signature");

        BiometricStepUpTokenResponse response = BiometricStepUpTokenResponse.builder()
                .stepUpToken("step-up-jwt")
                .expiresAt(Instant.parse("2026-02-20T17:05:00Z"))
                .build();

        when(biometricStepUpService.verifyChallenge(eq("tester@fivucsas.local"), any(BiometricVerifyChallengeRequest.class)))
                .thenReturn(response);

        mockMvc.perform(post("/api/v1/step-up/verify")
                        .with(user("tester@fivucsas.local"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.stepUpToken").value("step-up-jwt"));
    }

    @Test
    @DisplayName("Should return 400 for invalid request body")
    void shouldReturn400ForInvalidBody() throws Exception {
        String invalidBody = "{\"platform\":\"ANDROID\",\"publicKeyJwk\":{}}";

        mockMvc.perform(post("/api/v1/step-up/register-device")
                        .with(user("tester@fivucsas.local"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidBody))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 401 when authentication is missing")
    void shouldReturn401WhenAuthMissing() throws Exception {
        mockMvc.perform(post("/api/v1/auth/biometric/challenge"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/step-up/challenge"))
                .andExpect(status().isUnauthorized());
    }

    private BiometricRegisterDeviceRequest validRegisterRequest() throws Exception {
        BiometricRegisterDeviceRequest request = new BiometricRegisterDeviceRequest();
        request.setKeyId("key-123");
        request.setPlatform("ANDROID");
        JsonNode jwk = objectMapper.readTree("""
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "abc",
                  "y": "def"
                }
                """);
        request.setPublicKeyJwk(jwk);
        request.setDeviceLabel("Pixel 8");
        return request;
    }
}
