package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
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
class FingerprintAuthHandlerTest {

    @Mock private BiometricServicePort biometricServicePort;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private FingerprintAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnFingerprint() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.FINGERPRINT);
    }

    @Test
    void validate_WhenVerified_ShouldReturnSuccess() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);
        when(biometricServicePort.verifyFingerprint(userId, "base64data"))
                .thenReturn(Map.of("verified", true));

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", "base64data"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("verified", "true");
    }

    @Test
    void validate_WhenNotVerified_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);
        when(biometricServicePort.verifyFingerprint(userId, "baddata"))
                .thenReturn(Map.of("verified", false));

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", "baddata"));

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

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", "data"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void validate_WhenServiceError_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(biometricServicePort.verifyFingerprint(userId, "data"))
                .thenThrow(new RuntimeException("Connection refused"));

        StepResult result = handler.validate(session, step, Map.of("fingerprintData", "data"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("unavailable");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }
}
