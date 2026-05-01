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
 * Verifies a {@link AuthMethodType#FINGERPRINT} step via WebAuthn platform
 * authenticator. Per P1.4 (CLAUDE.md), the legacy server-side fingerprint
 * biometric path was removed — FINGERPRINT is delivered exclusively via
 * platform authenticator (transport contains {@code internal}).
 *
 * <p>Two-phase: client first POSTs {@code data.action="challenge"} to receive
 * a WebAuthn challenge + filtered {@code allowCredentials}; client then POSTs
 * the assertion in a second call.
 */
@Component
@RequiredArgsConstructor
public class FingerprintVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final WebAuthnVerifySupport support;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.FINGERPRINT;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        if ("challenge".equals(data.get("action"))) {
            return MfaStepResult.challenge(support.buildChallengeResponse(session, user, true));
        }
        return support.verifyAssertion(session, user, (String) data.get("assertion"));
    }
}
