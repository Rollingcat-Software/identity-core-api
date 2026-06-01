package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class QrCodeVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final QrCodeService qrCodeService;

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
        // P1-2 fix: validate against the token-keyed QrCodeService store
        // (qr:token:{token} → userId, written by QrCodeService.generateToken and
        // consumed by the working QrCodeAuthHandler). The previous
        // otpService.validate("2fa-qr:" + userId, token) read a Redis store that
        // NOTHING ever writes, so QR as a 2nd factor on /auth/mfa/step always failed.
        boolean ok = qrCodeService.validateToken(token, user.getId());
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
