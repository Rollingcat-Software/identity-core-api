package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Verifies a {@link AuthMethodType#PASSWORD} step of an N-step MFA flow.
 *
 * <p>Although {@code PASSWORD} is normally the first step of the flow (and was
 * already validated by {@code AuthenticateUserService} when the {@link MfaSession}
 * was minted), some flows include {@code PASSWORD} again at a later step as a
 * stronger reauthentication. Verifying it here keeps the per-method semantics
 * uniform across all 10 handler types.
 */
@Component
@RequiredArgsConstructor
public class PasswordVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final PasswordEncoder passwordEncoder;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.PASSWORD;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String password = (String) data.get("password");
        if (password == null || password.isBlank()) {
            return MfaStepResult.fail();
        }
        boolean ok = user.checkPassword(password, passwordEncoder);
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
