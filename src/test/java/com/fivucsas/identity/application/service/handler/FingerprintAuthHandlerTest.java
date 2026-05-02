package com.fivucsas.identity.application.service.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.WebAuthnCredential;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import com.fivucsas.identity.application.port.output.WebAuthnCredentialRepositoryPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FingerprintAuthHandlerTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private WebAuthnService webAuthnService;
    @Mock private WebAuthnCredentialRepositoryPort credentialRepository;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private FingerprintAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnFingerprint() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.FINGERPRINT);
    }

    @Test
    void validate_WhenChallengeAction_ShouldReturnChallenge() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(webAuthnService.generateChallenge(sessionId)).thenReturn("challengeBase64");
        when(webAuthnService.getRpId()).thenReturn("fivucsas.com");

        StepResult result = handler.validate(session, step, Map.of("action", "challenge"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("challenge", "challengeBase64");
        assertThat(result.data()).containsEntry("authenticatorAttachment", "platform");
        assertThat(result.data()).containsKey("rpId");
    }

    @Test
    void validate_WhenValidAssertion_ShouldReturnSuccess() {
        UUID sessionId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(sessionId);

        WebAuthnCredential credential = mock(WebAuthnCredential.class);
        User credUser = mock(User.class);
        when(credUser.getId()).thenReturn(userId);
        when(credential.getUser()).thenReturn(credUser);
        when(credential.getPublicKey()).thenReturn("publicKeyBase64");
        when(credential.getSignCount()).thenReturn(0L);

        String fingerprintData = encodePayload("credId", "authData", "clientData", "sig");

        when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(credential));
        when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "publicKeyBase64"))
                .thenReturn(true);
        when(webAuthnService.extractSignCount("authData")).thenReturn(1L);
        when(webAuthnService.validateSignCount(1L, 0L)).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", fingerprintData));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("verified", "true");
        verify(credential).updateSignCount(1L);
        verify(credentialRepository).save(credential);
    }

    @Test
    void validate_WhenNotVerified_ShouldReturnFailure() {
        UUID sessionId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(sessionId);

        WebAuthnCredential credential = mock(WebAuthnCredential.class);
        User credUser = mock(User.class);
        when(credUser.getId()).thenReturn(userId);
        when(credential.getUser()).thenReturn(credUser);
        when(credential.getPublicKey()).thenReturn("publicKeyBase64");

        String fingerprintData = encodePayload("credId", "authData", "clientData", "sig");

        when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(credential));
        when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "publicKeyBase64"))
                .thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", fingerprintData));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Fingerprint verification failed");
    }

    @Test
    void validate_WhenMissingData_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Fingerprint data is required");
    }

    @Test
    void validate_WhenNoUser_ShouldReturnFailure() {
        when(session.getUser()).thenReturn(null);

        String fingerprintData = encodePayload("credId", "authData", "clientData", "sig");
        StepResult result = handler.validate(session, step, Map.of("fingerprintData", fingerprintData));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void validate_WhenCredentialNotFound_ShouldReturnFailure() {
        User user = mock(User.class);
        when(session.getUser()).thenReturn(user);

        String fingerprintData = encodePayload("unknownCred", "authData", "clientData", "sig");

        when(credentialRepository.findByCredentialId("unknownCred")).thenReturn(Optional.empty());

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", fingerprintData));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Credential not registered");
    }

    @Test
    void validate_WhenCredentialBelongsToDifferentUser_ShouldReturnFailure() {
        UUID sessionUserId = UUID.randomUUID();
        UUID credentialUserId = UUID.randomUUID();

        User sessionUser = mock(User.class);
        when(sessionUser.getId()).thenReturn(sessionUserId);
        when(session.getUser()).thenReturn(sessionUser);

        WebAuthnCredential credential = mock(WebAuthnCredential.class);
        User credUser = mock(User.class);
        when(credUser.getId()).thenReturn(credentialUserId);
        when(credential.getUser()).thenReturn(credUser);

        String fingerprintData = encodePayload("credId", "authData", "clientData", "sig");

        when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(credential));

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", fingerprintData));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Credential does not belong to this user");
    }

    @Test
    void validate_WhenInvalidBase64_ShouldReturnFailure() {
        User user = mock(User.class);
        when(session.getUser()).thenReturn(user);

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", "not-valid-base64!!!"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid fingerprint data format");
    }

    @Test
    void validate_WhenServiceError_ShouldReturnFailure() {
        UUID sessionId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(sessionId);

        WebAuthnCredential credential = mock(WebAuthnCredential.class);
        User credUser = mock(User.class);
        when(credUser.getId()).thenReturn(userId);
        when(credential.getUser()).thenReturn(credUser);
        when(credential.getPublicKey()).thenReturn("publicKeyBase64");

        String fingerprintData = encodePayload("credId", "authData", "clientData", "sig");

        when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(credential));
        when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "publicKeyBase64"))
                .thenThrow(new RuntimeException("Connection refused"));

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", fingerprintData));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("unavailable");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }

    /**
     * Helper to create a base64-encoded JSON payload matching the frontend format.
     */
    private String encodePayload(String credentialId, String authenticatorData,
                                  String clientDataJSON, String signature) {
        try {
            Map<String, String> payload = Map.of(
                    "credentialId", credentialId,
                    "authenticatorData", authenticatorData,
                    "clientDataJSON", clientDataJSON,
                    "signature", signature
            );
            byte[] json = OBJECT_MAPPER.writeValueAsBytes(payload);
            return Base64.getEncoder().encodeToString(json);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
