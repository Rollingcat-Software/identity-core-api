package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.webauthn.WebAuthnService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class HardwareKeyAuthHandlerTest {

    @Mock private WebAuthnService webAuthnService;
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

        StepResult result = handler.validate(session, step, Map.of("action", "challenge"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("challenge", "challengeBase64");
        assertThat(result.data()).containsKey("rpId");
    }

    @Test
    void validate_WhenValidAssertion_ShouldReturnSuccess() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(sessionId);
        when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig"))
                .thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of(
                "credentialId", "credId",
                "authenticatorData", "authData",
                "clientDataJSON", "clientData",
                "signature", "sig"
        ));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void validate_WhenInvalidAssertion_ShouldReturnFailure() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(sessionId);
        when(webAuthnService.verifyAssertion(sessionId, "credId", "authData", "clientData", "sig"))
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
