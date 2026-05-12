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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SmsOtpAuthHandlerEdgeCasesTest {

    @Mock private OtpService otpService;
    @Mock private SmsService smsService;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private SmsOtpAuthHandler handler;

    // ── Both "send" and "send_otp" actions accepted (B1 fix) ────────────

    @Test
    void validate_WhenSendOtpAction_ShouldGenerateAndSendOtp() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn("+905551234567");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("654321");

        StepResult result = handler.validate(session, step, Map.of("action", "send_otp"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("otpSent", "true");
        verify(smsService).sendOtp("+905551234567", "654321");
    }

    @Test
    void validate_WhenSendAction_ShouldAlsoWork() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn("+905551234567");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("111222");

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("otpSent", "true");
        verify(smsService).sendOtp("+905551234567", "111222");
    }

    // ── Null / empty code variations ────────────────────────────────────

    @Test
    void validate_WhenCodeIsNull_ShouldReturnFailure() {
        Map<String, Object> data = new HashMap<>();
        data.put("code", null);

        StepResult result = handler.validate(session, step, data);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("SMS OTP code is required");
    }

    @Test
    void validate_WhenCodeIsEmptyString_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of("code", ""));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("SMS OTP code is required");
    }

    // ── Code expiration (OtpService returns false) ──────────────────────

    @Test
    void validate_WhenCodeExpired_ShouldReturnFailure() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(1);
        // OtpService.validateWithResult returns invalid when code is expired (not in Redis)
        when(otpService.validateWithResult("otp:" + sessionId + ":1:SMS_OTP", "123456"))
                .thenReturn(OtpService.ValidationResult.notFound());

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid or expired SMS OTP code");
    }

    // ── OTP code with leading zeros ─────────────────────────────────────

    @Test
    void validate_WhenCodeHasLeadingZeros_ShouldValidateExactString() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(2);
        when(otpService.validateWithResult("otp:" + sessionId + ":2:SMS_OTP", "007890"))
                .thenReturn(OtpService.ValidationResult.valid());

        StepResult result = handler.validate(session, step, Map.of("code", "007890"));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void validate_WhenCodeIsAllZeros_ShouldValidateExactString() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(2);
        when(otpService.validateWithResult("otp:" + sessionId + ":2:SMS_OTP", "000000"))
                .thenReturn(OtpService.ValidationResult.valid());

        StepResult result = handler.validate(session, step, Map.of("code", "000000"));

        assertThat(result.isSuccess()).isTrue();
    }

    // ── International phone number format ───────────────────────────────

    @Test
    void validate_WhenSendWithInternationalPhone_ShouldPassPhoneToSmsService() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn("+12025551234");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("987654");

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isTrue();
        verify(smsService).sendOtp("+12025551234", "987654");
    }

    @Test
    void validate_WhenSendWithTurkishPhone_ShouldPassPhoneToSmsService() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn("+905321234567");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("654321");

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isTrue();
        verify(smsService).sendOtp("+905321234567", "654321");
    }

    // ── Phone number is empty string (not null) ─────────────────────────

    @Test
    void validate_WhenSendWithEmptyPhoneNumber_ShouldFail() {
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn("");
        when(session.getUser()).thenReturn(user);

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("phone number");
    }

    // ── Resend OTP (calling send again for same session) ────────────────

    @Test
    void validate_WhenResendOtp_ShouldRegenerateAndSend() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getPhoneNumber()).thenReturn("+905551234567");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);

        // First send
        when(otpService.generate(anyString())).thenReturn("111111");
        handler.validate(session, step, Map.of("action", "send"));

        // Second send (resend) - otpService.generate overwrites the previous key
        when(otpService.generate(anyString())).thenReturn("222222");
        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isTrue();
        verify(smsService).sendOtp("+905551234567", "111111");
        verify(smsService).sendOtp("+905551234567", "222222");
        verify(otpService, times(2)).generate("otp:" + sessionId + ":1:SMS_OTP");
    }

    // ── OTP key format verification ─────────────────────────────────────

    @Test
    void validate_WhenDifferentStepOrders_ShouldUseDifferentOtpKeys() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);

        // Step order 1
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.validateWithResult("otp:" + sessionId + ":1:SMS_OTP", "111111"))
                .thenReturn(OtpService.ValidationResult.invalid(2L));
        handler.validate(session, step, Map.of("code", "111111"));
        verify(otpService).validateWithResult("otp:" + sessionId + ":1:SMS_OTP", "111111");

        // Step order 3
        when(step.getStepOrder()).thenReturn(3);
        when(otpService.validateWithResult("otp:" + sessionId + ":3:SMS_OTP", "222222"))
                .thenReturn(OtpService.ValidationResult.valid());
        StepResult result = handler.validate(session, step, Map.of("code", "222222"));
        assertThat(result.isSuccess()).isTrue();
        verify(otpService).validateWithResult("otp:" + sessionId + ":3:SMS_OTP", "222222");
    }

    // ── Unknown action should fall through to code validation ───────────

    @Test
    void validate_WhenUnknownAction_ShouldTreatAsCodeValidation() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.validateWithResult(anyString(), eq("123456")))
                .thenReturn(OtpService.ValidationResult.valid());

        StepResult result = handler.validate(session, step,
                Map.of("action", "unknown", "code", "123456"));

        assertThat(result.isSuccess()).isTrue();
    }

    // ── requiredDataFields ──────────────────────────────────────────────

    @Test
    void requiredDataFields_ShouldContainCode() {
        assertThat(handler.requiredDataFields()).containsExactly("code");
    }

    // ── Empty data map ──────────────────────────────────────────────────

    @Test
    void validate_WhenEmptyDataMap_ShouldReturnCodeRequired() {
        StepResult result = handler.validate(session, step, Map.of());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("SMS OTP code is required");
    }
}
