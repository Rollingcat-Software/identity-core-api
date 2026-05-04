package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.ManageDeviceUseCase;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import com.fivucsas.identity.application.service.WebAuthnCredentialService;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("WebAuthnController Tests")
class WebAuthnControllerTest {

    @Mock private ManageDeviceUseCase manageDeviceUseCase;
    @Mock private WebAuthnService webAuthnService;
    @Mock private WebAuthnCredentialRepositoryPort credentialRepository;
    @Mock private WebAuthnCredentialService webAuthnCredentialService;
    @Mock private UserRepository userRepository;

    @InjectMocks
    private DeviceController webAuthnController;

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
    @DisplayName("Registration Options (legacy path)")
    class RegistrationOptionsLegacy {

        @Test
        @DisplayName("Should return registration options with challenge")
        void shouldReturnRegistrationOptions() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
            when(webAuthnService.generateChallenge(any(UUID.class))).thenReturn("challengeBase64");
            when(webAuthnService.getRpId()).thenReturn("fivucsas.com");
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of());

            ResponseEntity<Map<String, Object>> response = webAuthnController.getRegistrationOptions(userId);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("challenge", "challengeBase64");
            assertThat(response.getBody()).containsEntry("rpId", "fivucsas.com");
            assertThat(response.getBody()).containsEntry("userName", "test@example.com");
        }

        @Test
        @DisplayName("Should throw when user not found")
        void shouldThrowWhenUserNotFound() {
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> webAuthnController.getRegistrationOptions(userId))
                    .isInstanceOf(RuntimeException.class);
        }
    }

    @Nested
    @DisplayName("Verify Registration (legacy path)")
    class VerifyRegistrationLegacy {

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
            verify(webAuthnCredentialService).saveCredential(any(WebAuthnCredential.class));
            verify(credentialRepository, never()).save(any(WebAuthnCredential.class));
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
        @DisplayName("Should delegate delete to WebAuthnCredentialService and return 204")
        void shouldDeleteCredential() {
            // Service handles existence + actual delete; controller just delegates.
            ResponseEntity<Void> response = webAuthnController.deleteCredential("credId");

            assertThat(response.getStatusCode().value()).isEqualTo(204);
            verify(webAuthnCredentialService).deleteByCredentialId("credId");
        }

        @Test
        @DisplayName("Should propagate ResourceNotFoundException from the service for unknown credentialId")
        void shouldThrowWhenDeletingNonExistent() {
            doThrow(new ResourceNotFoundException("Credential", "unknownCred"))
                    .when(webAuthnCredentialService).deleteByCredentialId("unknownCred");

            assertThatThrownBy(() -> webAuthnController.deleteCredential("unknownCred"))
                    .isInstanceOf(ResourceNotFoundException.class);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/webauthn/register-options")
    class RegisterOptions {

        @Test
        @DisplayName("Should generate registration options for authenticated user")
        void shouldGenerateOptionsForAuthenticatedUser() {
            setAuthContext("test@example.com");
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(webAuthnService.generateChallenge(any(UUID.class))).thenReturn("testChallenge");
            when(webAuthnService.getRpId()).thenReturn("fivucsas.com");
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of());

            ResponseEntity<Map<String, Object>> response = webAuthnController.registerOptions(null);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            Map<String, Object> body = response.getBody();
            assertThat(body).containsEntry("challenge", "testChallenge");
            assertThat(body).containsEntry("rpId", "fivucsas.com");
            assertThat(body).containsEntry("rpName", "Fivucsas Identity");
            assertThat(body).containsEntry("userName", "test@example.com");
            assertThat(body).containsEntry("userDisplayName", "John Doe");
            assertThat(body).containsKey("sessionId");
            assertThat(body).containsKey("authenticatorSelection");
            assertThat(body).containsEntry("timeout", 60000);
        }

        @Test
        @DisplayName("Should include excludeCredentials for existing registrations")
        void shouldExcludeExistingCredentials() {
            setAuthContext("test@example.com");
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(webAuthnService.generateChallenge(any(UUID.class))).thenReturn("ch");
            when(webAuthnService.getRpId()).thenReturn("rp.com");

            WebAuthnCredential existing = mock(WebAuthnCredential.class);
            when(existing.getCredentialId()).thenReturn("existingCredId");
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of(existing));

            ResponseEntity<Map<String, Object>> response = webAuthnController.registerOptions(null);

            assertThat(response.getBody().get("excludeCredentials")).isEqualTo(List.of("existingCredId"));
        }
    }

    @Nested
    @DisplayName("POST /api/v1/webauthn/register")
    class Register {

        @Test
        @DisplayName("Should register credential for authenticated user")
        void shouldRegisterForAuthenticatedUser() {
            setAuthContext("test@example.com");
            UUID sessionId = UUID.randomUUID();

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(webAuthnService.validateRegistrationChallenge(eq(sessionId), eq("clientData"))).thenReturn(true);
            when(credentialRepository.existsByCredentialId("newCredId")).thenReturn(false);

            WebAuthnCredential saved = mock(WebAuthnCredential.class);
            when(saved.getId()).thenReturn(UUID.randomUUID());
            when(webAuthnCredentialService.saveCredential(any(WebAuthnCredential.class))).thenReturn(saved);

            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "newCredId");
            request.put("publicKey", "pubKeyBase64");
            request.put("clientDataJSON", "clientData");
            request.put("deviceName", "My Laptop");

            ResponseEntity<Map<String, Object>> response = webAuthnController.register(request);

            assertThat(response.getStatusCode().value()).isEqualTo(201);
            assertThat(response.getBody()).containsEntry("success", true);
            assertThat(response.getBody()).containsEntry("credentialId", "newCredId");
            assertThat(response.getBody()).containsKey("id");
            verify(credentialRepository, never()).save(any(WebAuthnCredential.class));
        }

        @Test
        @DisplayName("Should reject missing publicKey")
        void shouldRejectMissingPublicKey() {
            setAuthContext("test@example.com");
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", UUID.randomUUID().toString());
            request.put("credentialId", "credId");

            ResponseEntity<Map<String, Object>> response = webAuthnController.register(request);

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).containsEntry("success", false);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/webauthn/authenticate-options")
    class AuthenticateOptions {

        @Test
        @DisplayName("Should return authentication options with allowCredentials")
        void shouldReturnAuthOptions() {
            WebAuthnCredential cred = mock(WebAuthnCredential.class);
            when(cred.getCredentialId()).thenReturn("credId1");
            when(cred.getTransports()).thenReturn("usb,nfc");

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of(cred));
            when(webAuthnService.generateChallenge(any(UUID.class))).thenReturn("authChallenge");
            when(webAuthnService.getRpId()).thenReturn("fivucsas.com");

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticateOptions(
                    Map.of("email", "test@example.com"));

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            Map<String, Object> body = response.getBody();
            assertThat(body).containsEntry("challenge", "authChallenge");
            assertThat(body).containsEntry("rpId", "fivucsas.com");
            assertThat(body).containsKey("sessionId");
            assertThat(body).containsKey("allowCredentials");

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> allowCreds = (List<Map<String, Object>>) body.get("allowCredentials");
            assertThat(allowCreds).hasSize(1);
            assertThat(allowCreds.get(0)).containsEntry("id", "credId1");
            assertThat(allowCreds.get(0)).containsEntry("type", "public-key");
        }

        @Test
        @DisplayName("Should return error when no email provided")
        void shouldRejectMissingEmail() {
            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticateOptions(
                    Map.of());

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("Should return error for unknown user without revealing existence")
        void shouldNotRevealUserExistence() {
            when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticateOptions(
                    Map.of("email", "unknown@example.com"));

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).containsEntry("message", "No WebAuthn credentials available");
        }

        @Test
        @DisplayName("Should return error when user has no credentials")
        void shouldRejectUserWithNoCredentials() {
            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(credentialRepository.findAllByUserId(userId)).thenReturn(List.of());

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticateOptions(
                    Map.of("email", "test@example.com"));

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).containsEntry("success", false);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/webauthn/authenticate")
    class Authenticate {

        @Test
        @DisplayName("Should authenticate successfully with valid assertion")
        void shouldAuthenticateSuccessfully() {
            UUID sessionId = UUID.randomUUID();
            WebAuthnCredential cred = mock(WebAuthnCredential.class);
            when(cred.getPublicKey()).thenReturn("pubKey");
            when(cred.getSignCount()).thenReturn(5L);
            when(cred.getUser()).thenReturn(testUser);

            when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(cred));
            when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "pubKey"))
                    .thenReturn(true);
            when(webAuthnService.extractSignCount("authData")).thenReturn(6L);
            when(webAuthnService.validateSignCount(6L, 5L)).thenReturn(true);

            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "credId");
            request.put("authenticatorData", "authData");
            request.put("clientDataJSON", "clientData");
            request.put("signature", "sig");

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticate(request);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).containsEntry("success", true);
            assertThat(response.getBody()).containsEntry("email", "test@example.com");
            assertThat(response.getBody()).containsEntry("userId", userId.toString());
            verify(webAuthnCredentialService).updateSignCount(cred, 6L);
            verify(credentialRepository, never()).save(any(WebAuthnCredential.class));
        }

        @Test
        @DisplayName("Should reject unknown credential")
        void shouldRejectUnknownCredential() {
            when(credentialRepository.findByCredentialId("unknownCred")).thenReturn(Optional.empty());

            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", UUID.randomUUID().toString());
            request.put("credentialId", "unknownCred");
            request.put("authenticatorData", "auth");
            request.put("clientDataJSON", "client");
            request.put("signature", "sig");

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticate(request);

            assertThat(response.getStatusCode().value()).isEqualTo(401);
            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("Should reject failed assertion verification")
        void shouldRejectFailedVerification() {
            UUID sessionId = UUID.randomUUID();
            WebAuthnCredential cred = mock(WebAuthnCredential.class);
            when(cred.getPublicKey()).thenReturn("pubKey");

            when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(cred));
            when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "pubKey"))
                    .thenReturn(false);

            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "credId");
            request.put("authenticatorData", "authData");
            request.put("clientDataJSON", "clientData");
            request.put("signature", "sig");

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticate(request);

            assertThat(response.getStatusCode().value()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should reject missing required fields")
        void shouldRejectMissingFields() {
            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", UUID.randomUUID().toString());
            request.put("credentialId", "credId");
            // Missing authenticatorData, clientDataJSON, signature

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticate(request);

            assertThat(response.getStatusCode().value()).isEqualTo(400);
            assertThat(response.getBody()).containsEntry("success", false);
        }

        @Test
        @DisplayName("Should reject sign-counter regression as cloned credential (P1-4)")
        void shouldRejectSignCountRegression() {
            UUID sessionId = UUID.randomUUID();
            WebAuthnCredential cred = mock(WebAuthnCredential.class);
            when(cred.getPublicKey()).thenReturn("pubKey");
            when(cred.getSignCount()).thenReturn(10L);
            // No need to stub getUser() — counter check happens before email log

            when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(cred));
            when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "pubKey"))
                    .thenReturn(true);
            when(webAuthnService.extractSignCount("authData")).thenReturn(5L);
            when(webAuthnService.validateSignCount(5L, 10L)).thenReturn(false);

            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "credId");
            request.put("authenticatorData", "authData");
            request.put("clientDataJSON", "clientData");
            request.put("signature", "sig");

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticate(request);

            assertThat(response.getStatusCode().value()).isEqualTo(401);
            assertThat(response.getBody()).containsEntry("success", false);
            verify(webAuthnCredentialService, never()).updateSignCount(any(), anyLong());
            verify(credentialRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should not save when counter equals stored but is both-zero (per spec note)")
        void shouldAcceptBothZeroWithoutSave() {
            UUID sessionId = UUID.randomUUID();
            WebAuthnCredential cred = mock(WebAuthnCredential.class);
            when(cred.getPublicKey()).thenReturn("pubKey");
            when(cred.getSignCount()).thenReturn(0L);
            when(cred.getUser()).thenReturn(testUser);

            when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(cred));
            when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "pubKey"))
                    .thenReturn(true);
            when(webAuthnService.extractSignCount("authData")).thenReturn(0L);
            when(webAuthnService.validateSignCount(0L, 0L)).thenReturn(true);

            Map<String, Object> request = new HashMap<>();
            request.put("sessionId", sessionId.toString());
            request.put("credentialId", "credId");
            request.put("authenticatorData", "authData");
            request.put("clientDataJSON", "clientData");
            request.put("signature", "sig");

            ResponseEntity<Map<String, Object>> response = webAuthnController.authenticate(request);

            assertThat(response.getStatusCode().value()).isEqualTo(200);
            // Controller delegates to the service; the service no-ops when the
            // new count is not strictly greater (spec-compliant both-zero case).
            verify(webAuthnCredentialService).updateSignCount(cred, 0L);
            verify(credentialRepository, never()).save(any());
        }
    }

    private void setAuthContext(String email) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(email, null, List.of()));
    }
}
