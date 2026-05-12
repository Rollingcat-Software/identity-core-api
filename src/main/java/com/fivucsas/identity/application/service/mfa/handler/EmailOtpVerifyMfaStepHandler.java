package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.exception.OtpAttemptsExhaustedException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
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
        // Cache user-id once — keeps the entity.User boundary surface
        // (ArchUnit UserDomainBoundaryTest) at a single call site for this
        // handler, matching FaceAuthHandler / FaceVerifyMfaStepHandler.
        java.util.UUID userId = user.getId();
        // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §OTP-exhausted — propagate
        // the NIST 800-63B 5-strike exhaustion state instead of letting the
        // boolean overload swallow it.
        OtpService.ValidationResult result =
                otpService.validateWithResult(TWO_FA_OTP_PREFIX + userId, code);
        if (result.isExhausted()) {
            log.warn("MFA EMAIL_OTP attempts exhausted — userId={}, sessionId={} (user must request a new code)",
                    userId, session.getId());
            throw new OtpAttemptsExhaustedException();
        }
        return result.isValid() ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
