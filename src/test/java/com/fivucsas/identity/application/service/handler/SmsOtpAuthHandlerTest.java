package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SmsOtpAuthHandlerTest {

    @Mock private OtpService otpService;
    @Mock private SmsService smsService;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private SmsOtpAuthHandler handler;

    @Test
    void getMethodType_ShouldReturnSmsOtp() {
        assertThat(handler.getMethodType()).isEqualTo(AuthMethodType.SMS_OTP);
    }

    @Test
    void validate_WhenValidCode_ShouldReturnSuccess() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(2);
        when(otpService.validate("otp:" + sessionId + ":2:SMS_OTP", "123456")).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void validate_WhenInvalidCode_ShouldReturnFailure() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(2);
        when(otpService.validate(anyString(), eq("999999"))).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", "999999"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid or expired SMS OTP code");
    }

    @Test
    void validate_WhenMissingCode_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("SMS OTP code is required");
    }

    @Test
    void validate_WhenSendAction_ShouldGenerateAndSendOtp() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn("+905551234567");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("654321");

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("otpSent", "true");
        verify(smsService).sendOtp("+905551234567", "654321");
    }

    @Test
    void validate_WhenSendActionWithoutUser_ShouldFail() {
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    @Test
    void validate_WhenSendActionWithNoPhone_ShouldFail() {
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn(null);
        when(session.getUser()).thenReturn(user);

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("phone number");
    }

    @Test
    void requiresEnrollment_ShouldReturnFalse() {
        assertThat(handler.requiresEnrollment()).isFalse();
    }
}
