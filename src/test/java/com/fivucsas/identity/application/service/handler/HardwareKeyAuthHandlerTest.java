package com.fivucsas.identity.application.service.handler;

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

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HardwareKeyAuthHandlerTest {

    @Mock private WebAuthnService webAuthnService;
    @Mock private WebAuthnCredentialRepositoryPort credentialRepository;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private HardwareKeyAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnHardwareKey() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.HARDWARE_KEY);
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
        assertThat(result.data()).containsKey("rpId");
    }

    @Test
    void validate_WhenValidAssertion_ShouldReturnSuccess() {
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
        when(credential.getSignCount()).thenReturn(0L);

        when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(credential));
        when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "publicKeyBase64"))
                .thenReturn(true);
        when(webAuthnService.extractSignCount("authData")).thenReturn(1L);

        StepResult result = handler.validate(session, step, Map.of(
                "credentialId", "credId",
                "authenticatorData", "authData",
                "clientDataJSON", "clientData",
                "signature", "sig"
        ));

        assertThat(result.isSuccess()).isTrue();
        verify(credential).updateSignCount(1L);
        verify(credentialRepository).save(credential);
    }

    @Test
    void validate_WhenCredentialNotFound_ShouldReturnFailure() {
        User user = mock(User.class);
        when(session.getUser()).thenReturn(user);
        when(credentialRepository.findByCredentialId("unknownCred")).thenReturn(Optional.empty());

        StepResult result = handler.validate(session, step, Map.of(
                "credentialId", "unknownCred",
                "authenticatorData", "authData",
                "clientDataJSON", "clientData",
                "signature", "sig"
        ));

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

        when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(credential));

        StepResult result = handler.validate(session, step, Map.of(
                "credentialId", "credId",
                "authenticatorData", "authData",
                "clientDataJSON", "clientData",
                "signature", "sig"
        ));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Credential does not belong to this user");
    }

    @Test
    void validate_WhenInvalidAssertion_ShouldReturnFailure() {
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

        when(credentialRepository.findByCredentialId("credId")).thenReturn(Optional.of(credential));
        when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig", "publicKeyBase64"))
                .thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of(
                "credentialId", "credId",
                "authenticatorData", "authData",
                "clientDataJSON", "clientData",
                "signature", "sig"
        ));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Hardware key verification failed");
    }

    @Test
    void validate_WhenMissingCredentialId_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Credential ID is required");
    }

    @Test
    void validate_WhenNoUser_ShouldReturnFailure() {
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("credentialId", "cred"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }
}
