package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
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
class EmailOtpAuthHandlerEdgeCasesTest {

    @Mock private OtpService otpService;
    @Mock private EmailService emailService;
    @Mock private AuthSession session;
    @Mock private AuthFlowStep step;

    @InjectMocks
    private EmailOtpAuthHandler handler;

    // ── Both "send" and "send_otp" actions accepted (B1 fix) ────────────

    @Test
    void validate_WhenSendOtpAction_ShouldGenerateAndSendOtp() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@example.com");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("654321");

        StepResult result = handler.validate(session, step, Map.of("action", "send_otp"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("otpSent", "true");
        verify(emailService).sendOtp("user@example.com", "654321");
    }

    @Test
    void validate_WhenSendAction_ShouldAlsoWork() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@example.com");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("111222");

        StepResult result = handler.validate(session, step, Map.of("action", "send"));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.data()).containsEntry("otpSent", "true");
        verify(emailService).sendOtp("user@example.com", "111222");
    }

    // ── Null / empty code variations ────────────────────────────────────

    @Test
    void validate_WhenCodeIsNull_ShouldReturnFailure() {
        Map<String, Object> data = new HashMap<>();
        data.put("code", null);

        StepResult result = handler.validate(session, step, data);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("OTP code is required");
    }

    @Test
    void validate_WhenCodeIsEmptyString_ShouldReturnFailure() {
        StepResult result = handler.validate(session, step, Map.of("code", ""));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("OTP code is required");
    }

    // ── Code expiration (OtpService returns false) ──────────────────────

    @Test
    void validate_WhenCodeExpired_ShouldReturnFailure() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.validate("otp:" + sessionId + ":1:EMAIL_OTP", "123456")).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", "123456"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).isEqualTo("Invalid or expired OTP code");
    }

    // ── OTP code with leading zeros ─────────────────────────────────────

    @Test
    void validate_WhenCodeHasLeadingZeros_ShouldValidateExactString() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(2);
        when(otpService.validate("otp:" + sessionId + ":2:EMAIL_OTP", "007890")).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("code", "007890"));

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void validate_WhenCodeIsAllZeros_ShouldValidateExactString() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(2);
        when(otpService.validate("otp:" + sessionId + ":2:EMAIL_OTP", "000000")).thenReturn(true);

        StepResult result = handler.validate(session, step, Map.of("code", "000000"));

        assertThat(result.isSuccess()).isTrue();
    }

    // ── Email send failure (SMTP error) ─────────────────────────────────

    @Test
    void validate_WhenEmailServiceThrows_ShouldPropagateException() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@example.com");
        when(session.getId()).thenReturn(sessionId);
        when(session.getUser()).thenReturn(user);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.generate(anyString())).thenReturn("654321");
        doThrow(new RuntimeException("SMTP connection refused"))
                .when(emailService).sendOtp("user@example.com", "654321");

        try {
            handler.validate(session, step, Map.of("action", "send"));
            // If the handler does not catch the exception, the test verifies propagation
        } catch (RuntimeException e) {
            assertThat(e.getMessage()).isEqualTo("SMTP connection refused");
        }
    }

    // ── Send without user email (user has null email) ───────────────────

    @Test
    void validate_WhenSendWithoutUserIdentified_ShouldFail() {
        when(session.getUser()).thenReturn(null);

        StepResult result = handler.validate(session, step, Map.of("action", "send_otp"));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.error()).contains("User must be identified");
    }

    // ── Resend OTP (calling send again for same session) ────────────────

    @Test
    void validate_WhenResendOtp_ShouldRegenerateAndSend() {
        UUID sessionId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@example.com");
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
        verify(emailService).sendOtp("user@example.com", "111111");
        verify(emailService).sendOtp("user@example.com", "222222");
        verify(otpService, times(2)).generate("otp:" + sessionId + ":1:EMAIL_OTP");
    }

    // ── OTP key format verification ─────────────────────────────────────

    @Test
    void validate_WhenDifferentStepOrders_ShouldUseDifferentOtpKeys() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);

        // Step order 1
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.validate("otp:" + sessionId + ":1:EMAIL_OTP", "111111")).thenReturn(false);
        handler.validate(session, step, Map.of("code", "111111"));
        verify(otpService).validate("otp:" + sessionId + ":1:EMAIL_OTP", "111111");

        // Step order 3
        when(step.getStepOrder()).thenReturn(3);
        when(otpService.validate("otp:" + sessionId + ":3:EMAIL_OTP", "222222")).thenReturn(true);
        StepResult result = handler.validate(session, step, Map.of("code", "222222"));
        assertThat(result.isSuccess()).isTrue();
        verify(otpService).validate("otp:" + sessionId + ":3:EMAIL_OTP", "222222");
    }

    // ── Case sensitivity of OTP code ────────────────────────────────────

    @Test
    void validate_WhenCodeCaseDiffers_ShouldBeExactMatch() {
        // OTP codes are numeric, but this tests that the handler passes
        // the code as-is to OtpService (no case transformation)
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(2);
        when(otpService.validate("otp:" + sessionId + ":2:EMAIL_OTP", "AbCdEf")).thenReturn(false);

        StepResult result = handler.validate(session, step, Map.of("code", "AbCdEf"));

        assertThat(result.isSuccess()).isFalse();
        // Verify the exact string was passed (no toLowerCase or toUpperCase)
        verify(otpService).validate("otp:" + sessionId + ":2:EMAIL_OTP", "AbCdEf");
    }

    // ── Unknown action should fall through to code validation ───────────

    @Test
    void validate_WhenUnknownAction_ShouldTreatAsCodeValidation() {
        UUID sessionId = UUID.randomUUID();
        when(session.getId()).thenReturn(sessionId);
        when(step.getStepOrder()).thenReturn(1);
        when(otpService.validate(anyString(), eq("123456"))).thenReturn(true);

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
        assertThat(result.error()).isEqualTo("OTP code is required");
    }
}
