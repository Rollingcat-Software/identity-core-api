package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class EmailOtpVerifyMfaStepHandler implements VerifyMfaStepHandler {

    /** Must match the prefix used by AuthController.send2FAEmail (TWO_FA_OTP_PREFIX). */
    private static final String TWO_FA_OTP_PREFIX = "2fa-login:";

    private final OtpService otpService;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.EMAIL_OTP;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String code = (String) data.get("code");
        if (code == null || code.isBlank()) {
            return MfaStepResult.fail();
        }
        boolean ok = otpService.validate(TWO_FA_OTP_PREFIX + user.getId(), code);
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
