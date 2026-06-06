package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.MarkPhoneVerifiedPort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.infrastructure.sms.VerifiableSmsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class SmsOtpVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final SmsService smsService;
    private final OtpService otpService;
    // F2 (2026-06-06): a verified SMS_OTP step proves phone ownership, so mark
    // phone_number_verified (keyed by userId → adapter owns the entity.User write,
    // keeping this handler off the entity.User boundary). Phone stays OPTIONAL —
    // this only corrects the claim WHEN the user authenticates by SMS_OTP.
    private final MarkPhoneVerifiedPort markPhoneVerifiedPort;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.SMS_OTP;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String code = (String) data.get("code");
        if (code == null || code.isBlank()) {
            return MfaStepResult.fail();
        }
        // Prefer Twilio Verify (or any VerifiableSmsService) — it owns the OTP
        // lifecycle remotely. Fall back to local Redis-backed OtpService for
        // dev/no-op gateway.
        if (smsService instanceof VerifiableSmsService verifiable) {
            String phone = user.getPhoneNumber();
            if (phone == null || phone.isBlank()) {
                return MfaStepResult.fail();
            }
            if (verifiable.verifyCode(phone, code)) {
                markPhoneVerifiedPort.markPhoneVerified(session.getUserId());
                return MfaStepResult.ok();
            }
            return MfaStepResult.fail();
        }
        boolean ok = otpService.validate("2fa-sms:" + user.getId(), code);
        if (ok) {
            markPhoneVerifiedPort.markPhoneVerified(session.getUserId());
        }
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
