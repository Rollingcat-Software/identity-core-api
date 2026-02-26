package com.fivucsas.identity.controller;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.repository.WebAuthnCredentialRepository;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("WebAuthnController Tests")
class WebAuthnControllerTest {

    @Mock private WebAuthnService webAuthnService;
    @Mock private WebAuthnCredentialRepository credentialRepository;
    @Mock private UserRepository userRepository;

    @InjectMocks
    private WebAuthnController webAuthnController;

    private UUID userId;
    private User testUser;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .email("test@example.com")
                .passwordHash("$2a$10$hash")
                .firstName("John")
                .lastName("Doe")
                .status(UserStatus.ACTIVE)
                .build();
    }

    @Nested
    @DisplayName("Registration Options")
    class RegistrationOptions {

        @Test
        @DisplayName("Should return registration options with challenge")
        void shouldReturnRegistrationOptions() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(webAuthnService.generateChallenge(any(UUID.class))).thenReturn("challengeBase64");
            when(webAuthnService.getRpId()).thenReturn("fivucsas.rollingcatsoftware.com");
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of());

            ResponseEntity<Map<String, Object>> response = webAuthnController.getRegistrationOptions(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("challenge", "challengeBase64");
            assertThat(response.getBody()).containsEntry("rpId", "fivucsas.rollingcatsoftware.com");
            assertThat(response.getBody()).containsEntry("userName", "test@example.com");
        }

        @Test
        @DisplayName("Should throw when user not found")
        void shouldThrowWhenUserNotFound() {
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> webAuthnController.getRegistrationOptions(userId))
                    .isInstanceOf(EntityNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("Verify Registration")
    class VerifyRegistration {

        @Test
        @DisplayName("Should register credential successfully")
        void shouldRegisterCredential() {
            UUID sessionId = UUID.randomUUID();
            Map<String, Object> request = new HashMap<>();
            request.put("userId", userId.toString());
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "credId123");
            request.put("publicKey", "publicKeyBase64");
            request.put("clientDataJSON", "clientDataB64");

            when(webAuthnService.validateRegistrationChallenge(sessionId, "clientDataB64")).thenReturn(true);
            when(credentialRepository.existsByCredentialId("credId123")).thenReturn(false);
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));

            ResponseEntity<Map<String, Object>> response = webAuthnController.verifyRegistration(request);

            assertThat(response.getStatusCode().value()).isEqualTo(201);
            assertThat(response.getBody()).containsEntry("success", true);
            verify(credentialRepository).save(any(WebAuthnCredential.class));
        }

        @Test
        @DisplayName("Should reject when credential already exists")
        void shouldRejectDuplicate() {
            UUID sessionId = UUID.randomUUID();
            Map<String, Object> request = new HashMap<>();
            request.put("userId", userId.toString());
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "credId123");
            request.put("publicKey", "publicKeyBase64");
            request.put("clientDataJSON", "clientDataB64");

            when(webAuthnService.validateRegistrationChallenge(sessionId, "clientDataB64")).thenReturn(true);
            when(credentialRepository.existsByCredentialId("credId123")).thenReturn(true);

            ResponseEntity<Map<String, Object>> response = webAuthnController.verifyRegistration(request);

            assertThat(response.getStatusCode().value()).isEqualTo(409);
        }

        @Test
        @DisplayName("Should reject invalid challenge")
        void shouldRejectInvalidChallenge() {
            UUID sessionId = UUID.randomUUID();
            Map<String, Object> request = new HashMap<>();
            request.put("userId", userId.toString());
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "credId123");
            request.put("publicKey", "publicKeyBase64");
            request.put("clientDataJSON", "invalidClientData");

            when(webAuthnService.validateRegistrationChallenge(sessionId, "invalidClientData")).thenReturn(false);

            ResponseEntity<Map<String, Object>> response = webAuthnController.verifyRegistration(request);

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("Should reject missing credentials fields")
        void shouldRejectMissingFields() {
            Map<String, Object> request = new HashMap<>();
            request.put("userId", userId.toString());
            request.put("sessionId", UUID.randomUUID().toString());

            ResponseEntity<Map<String, Object>> response = webAuthnController.verifyRegistration(request);

            assertThat(response.getStatusCode().value()).isEqualTo(400);
        }
    }

    @Nested
    @DisplayName("Credential Management")
    class CredentialManagement {

        @Test
        @DisplayName("Should list credentials for user")
        void shouldListCredentials() {
            WebAuthnCredential cred = mock(WebAuthnCredential.class);
            when(cred.getId()).thenReturn(UUID.randomUUID());
            when(cred.getCredentialId()).thenReturn("credId");
            when(cred.getDeviceName()).thenReturn("My Phone");
            when(cred.getCreatedAt()).thenReturn(Instant.now());
            when(cred.getLastUsedAt()).thenReturn(null);

            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of(cred));

            ResponseEntity<List<Map<String, Object>>> response = webAuthnController.listCredentials(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).hasSize(1);
            assertThat(response.getBody().get(0)).containsEntry("credentialId", "credId");
        }

        @Test
        @DisplayName("Should delete credential")
        void shouldDeleteCredential() {
            when(credentialRepository.existsByCredentialId("credId")).thenReturn(true);

            ResponseEntity<Void> response = webAuthnController.deleteCredential("credId");

            assertThat(response.getStatusCode().value()).isEqualTo(204);
            verify(credentialRepository).deleteByCredentialId("credId");
        }

        @Test
        @DisplayName("Should throw when deleting non-existent credential")
        void shouldThrowWhenDeletingNonExistent() {
            when(credentialRepository.existsByCredentialId("unknownCred")).thenReturn(false);

            assertThatThrownBy(() -> webAuthnController.deleteCredential("unknownCred"))
                    .isInstanceOf(EntityNotFoundException.class);
        }
    }
}
