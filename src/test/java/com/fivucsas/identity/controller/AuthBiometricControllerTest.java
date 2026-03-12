package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.BiometricDeviceRequest;
import com.fivucsas.identity.application.dto.command.BiometricVerifyRequest;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.StepUpChallengeResponse;
import com.fivucsas.identity.application.dto.response.StepUpVerifyResponse;
import com.fivucsas.identity.application.port.input.StepUpAuthUseCase;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.security.RbacAuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthBiometricController Tests")
class AuthBiometricControllerTest {

    @Mock private StepUpAuthUseCase stepUpAuthUseCase;
    @Mock private RbacAuthorizationService rbacService;

    @InjectMocks
    private AuthBiometricController controller;

    private UUID userId;
    private UUID tenantId;
    private User testUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
        Tenant tenant = Tenant.builder()
                .id(tenantId)
                .name("Test Tenant")
                .slug("test-tenant")
                .contactEmail("admin@test.com")
                .status(TenantStatus.ACTIVE)
                .build();
        testUser = User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash("$2a$10$hash")
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .tenant(tenant)
                .build();
    }

    @Nested
    @DisplayName("Register Device")
    class RegisterDevice {

        @Test
        @DisplayName("Should register device with valid platform")
        void shouldRegisterDeviceWithValidPlatform() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            DeviceResponse mockResponse = new DeviceResponse(UUID.randomUUID(), "keyId123", "ANDROID", "ECDSA-P256");
            when(stepUpAuthUseCase.registerStepUpDevice(eq(userId), eq(tenantId), any())).thenReturn(mockResponse);

            BiometricDeviceRequest request = new BiometricDeviceRequest("keyId123", "android", "jwkData");
            ResponseEntity<DeviceResponse> response = controller.registerDevice(request);

            assertThat(response.getStatusCode().value()).isEqualTo(201);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().keyId()).isEqualTo("keyId123");
        }

        @Test
        @DisplayName("Should reject invalid platform value")
        void shouldRejectInvalidPlatform() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));

            BiometricDeviceRequest request = new BiometricDeviceRequest("keyId123", "invalid_platform", "jwkData");

            assertThatThrownBy(() -> controller.registerDevice(request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Invalid platform")
                    .hasMessageContaining("invalid_platform");
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

            BiometricDeviceRequest request = new BiometricDeviceRequest("keyId123", "android", "jwkData");

            assertThatThrownBy(() -> controller.registerDevice(request))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }

    @Nested
    @DisplayName("Create Challenge")
    class CreateChallenge {

        @Test
        @DisplayName("Should create challenge for authenticated user")
        void shouldCreateChallenge() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            StepUpChallengeResponse mockResponse = new StepUpChallengeResponse("challenge-nonce-123");
            when(stepUpAuthUseCase.requestChallenge(eq(userId), any())).thenReturn(mockResponse);

            ResponseEntity<Map<String, Object>> response = controller.createChallenge();

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("challengeId", "challenge-nonce-123");
            assertThat(response.getBody()).containsEntry("nonce", "challenge-nonce-123");
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

            assertThatThrownBy(() -> controller.createChallenge())
                    .isInstanceOf(UnauthorizedException.class);
        }
    }

    @Nested
    @DisplayName("Verify Signature")
    class VerifySignature {

        @Test
        @DisplayName("Should verify signature successfully")
        void shouldVerifySignature() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.of(testUser));
            StepUpVerifyResponse mockResponse = new StepUpVerifyResponse(true, "step-up-token-123");
            when(stepUpAuthUseCase.verifyChallenge(eq(userId), any())).thenReturn(mockResponse);

            BiometricVerifyRequest request = new BiometricVerifyRequest("challenge-1", "keyId-1", "sig-base64");
            ResponseEntity<Map<String, Object>> response = controller.verifySignature(request);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("verified", true);
            assertThat(response.getBody()).containsEntry("stepUpToken", "step-up-token-123");
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when not authenticated")
        void shouldThrowWhenNotAuthenticated() {
            when(rbacService.getCurrentUser()).thenReturn(Optional.empty());

            BiometricVerifyRequest request = new BiometricVerifyRequest("challenge-1", "keyId-1", "sig-base64");

            assertThatThrownBy(() -> controller.verifySignature(request))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }
}
