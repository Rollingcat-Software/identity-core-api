package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class QrCodeAuthHandlerTest {

    @Mock private QrCodeService qrCodeService;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private QrCodeAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnQrCode() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.QR_CODE);
    }

    @Test
    void validate_WhenValidToken_ShouldReturnSuccess() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(qrCodeService.validateToken("valid-token", userId)).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("qrToken", "valid-token"));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void validate_WhenInvalidToken_ShouldReturnFailure() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(session.getUser()).thenReturn(user);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(qrCodeService.validateToken("bad-token", userId)).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("qrToken", "bad-token"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("Invalid or expired");
    }

    @Test
    void validate_WhenNoToken_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("QR token is required");
    }

    @Test
    void validate_WhenNoUser_ShouldReturnFailure() {
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("qrToken", "some-token"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void requiresEnrollment_ShouldReturnTrue() {
        assertThat(handler.requiresEnrollment()).isTrue();
    }

    @Test
    void requiredDataFields_ShouldContainQrToken() {
        assertThat(handler.requiredDataFields()).containsExactly("qrToken");
    }
}
