package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.MarkPhoneVerifiedPort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * F2 (2026-06-06): a successful SMS_OTP MFA login step must set
 * {@code phone_number_verified} (via {@link MarkPhoneVerifiedPort}); a failed step
 * must NOT. Phone stays optional — the flag is only corrected on SMS_OTP auth.
 */
@ExtendWith(MockitoExtension.class)
class SmsOtpVerifyMfaStepHandlerTest {

    @Mock private SmsService smsService;
    @Mock private OtpService otpService;
    @Mock private MarkPhoneVerifiedPort markPhoneVerifiedPort;
    @Mock private MfaSession session;
    @Mock private User user;

    @InjectMocks
    private SmsOtpVerifyMfaStepHandler handler;

    @Test
    void supports_ShouldReturnSmsOtp() {
        assertThat(handler.supports()).isEqualTo(AuthMethodType.SMS_OTP);
    }

    @Test
    void verify_WhenLocalOtpValid_ShouldMarkPhoneVerified() {
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(session.getUserId()).thenReturn(userId);
        when(otpService.validate("2fa-sms:" + userId, "123456")).thenReturn(true);

        MfaStepResult result = handler.verify(session, user, Map.of("code", "123456"));

        assertThat(result.valid()).isTrue();
        verify(markPhoneVerifiedPort).markPhoneVerified(userId);
    }

    @Test
    void verify_WhenLocalOtpInvalid_ShouldNotMarkPhoneVerified() {
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(otpService.validate("2fa-sms:" + userId, "000000")).thenReturn(false);

        MfaStepResult result = handler.verify(session, user, Map.of("code", "000000"));

        assertThat(result.valid()).isFalse();
        verify(markPhoneVerifiedPort, never()).markPhoneVerified(any());
    }

    @Test
    void verify_WhenCodeMissing_ShouldFailWithoutMarkingPhone() {
        MfaStepResult result = handler.verify(session, user, Map.of());

        assertThat(result.valid()).isFalse();
        verify(markPhoneVerifiedPort, never()).markPhoneVerified(any());
        verify(otpService, never()).validate(anyString(), anyString());
    }
}
