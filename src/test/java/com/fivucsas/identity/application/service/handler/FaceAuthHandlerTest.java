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

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FaceAuthHandlerTest {

    @Mock private BiometricServicePort biometricServicePort;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private FaceAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnFace() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.FACE);
    }

    @Test
    void validate_WhenVerified_ShouldReturnSuccess() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);

        String fakeImage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        when(biometricServicePort.verifyFace(eq(userId), any()))
                .thenReturn(Map.of("verified", true, "confidence", 0.95));

        StepResult result = handler.validate(session, step, Map.of("image", fakeImage));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void validate_WhenConfidenceBelowThreshold_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);

        String fakeImage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        when(biometricServicePort.verifyFace(eq(userId), any()))
                .thenReturn(Map.of("verified", false, "confidence", 0.4));

        StepResult result = handler.validate(session, step, Map.of("image", fakeImage));

        assertThat(result.isSuccess()).isFalse();
    }

    /**
     * P0-#10 regression: previously a high `confidence` value would override
     * server-side `verified=false` via a hardcoded 0.7 cosine fallback.
     * The fix removes that fallback — handler now trusts ONLY `verified`.
     */
    @Test
    void validate_WhenVerifiedFalseButConfidenceHigh_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);

        String fakeImage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        when(biometricServicePort.verifyFace(eq(userId), any()))
                .thenReturn(Map.of("verified", false, "confidence", 0.95));

        StepResult result = handler.validate(session, step, Map.of("image", fakeImage));

        assertThat(result.isSuccess())
                .as("server verified=false must NOT be overridden by high confidence")
                .isFalse();
    }

    /**
     * P0-#10: even when confidence is low, if the server (which applies the
     * adaptive aging threshold) reports verified=true, we trust it.
     */
    @Test
    void validate_WhenVerifiedTrueButConfidenceLow_ShouldReturnSuccess() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(session.getUser()).thenReturn(user);

        String fakeImage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        when(biometricServicePort.verifyFace(eq(userId), any()))
                .thenReturn(Map.of("verified", true, "confidence", 0.5));

        StepResult result = handler.validate(session, step, Map.of("image", fakeImage));

        assertThat(result.isSuccess())
                .as("server verified=true must be trusted (server-side adaptive threshold)")
                .isTrue();
    }

    /**
     * P0-#10: missing `verified` field is treated as hard-reject (fail-closed)
     * and logged at ERROR level. Previously the handler would silently fall
     * through to the 0.7 confidence fallback.
     */
    @Test
    void validate_WhenVerifiedFieldMissing_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);

        String fakeImage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        Map<String, Object> noVerifiedField = new HashMap<>();
        noVerifiedField.put("confidence", 0.99);
        when(biometricServicePort.verifyFace(eq(userId), any()))
                .thenReturn(noVerifiedField);

        StepResult result = handler.validate(session, step, Map.of("image", fakeImage));

        assertThat(result.isSuccess())
                .as("missing `verified` field must fail closed, not fall back to confidence")
                .isFalse();
    }

    @Test
    void validate_WhenNoImage_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Face image is required");
    }

    @Test
    void validate_WhenNoUser_ShouldReturnFailure() {
        String fakeImage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("image", fakeImage));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void validate_WhenServiceError_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);

        String fakeImage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        when(biometricServicePort.verifyFace(eq(userId), any()))
                .thenThrow(new RuntimeException("Service down"));

        StepResult result = handler.validate(session, step, Map.of("image", fakeImage));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("unavailable");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }
}
