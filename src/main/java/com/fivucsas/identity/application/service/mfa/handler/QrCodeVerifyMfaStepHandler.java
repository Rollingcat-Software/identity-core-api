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
public class QrCodeVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final OtpService otpService;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.QR_CODE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String token = (String) data.get("token");
        if (token == null || token.isBlank()) {
            return MfaStepResult.fail();
        }
        boolean ok = otpService.validate("2fa-qr:" + user.getId(), token);
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
