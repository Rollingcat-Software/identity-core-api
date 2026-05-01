package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Verifies a {@link AuthMethodType#HARDWARE_KEY} step via WebAuthn cross-platform
 * (roaming) authenticator (e.g. YubiKey, Titan).
 *
 * <p>Differs from {@link FingerprintVerifyMfaStepHandler} only in the transport
 * filter applied during the challenge phase: roaming authenticators do NOT
 * carry the {@code internal} transport, so {@code wantPlatform=false}.
 */
@Component
@RequiredArgsConstructor
public class HardwareKeyVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final WebAuthnVerifySupport support;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.HARDWARE_KEY;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        if ("challenge".equals(data.get("action"))) {
            return MfaStepResult.challenge(support.buildChallengeResponse(session, user, false));
        }
        return support.verifyAssertion(session, user, (String) data.get("assertion"));
    }
}
