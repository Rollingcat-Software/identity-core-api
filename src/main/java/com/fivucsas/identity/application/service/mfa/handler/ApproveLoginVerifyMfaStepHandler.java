package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.approvelogin.ApproveLoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Verifies an {@link AuthMethodType#APPROVE_LOGIN} step — number-matching
 * cross-device approval as a mid-MFA-flow FACTOR (not a usernameless Layer-1).
 *
 * <p>Two-phase, like the WebAuthn / QR handlers:
 * <ol>
 *   <li>client POSTs {@code data.action="challenge"} → we create a STEP-BOUND
 *       {@link ApproveLoginService} session for THIS user and return its
 *       {@code matchNumber} + {@code approveSessionId}. The web shows the number
 *       and polls; the user's already-signed-in phone sees the SAME pending
 *       request (it surfaces in {@code /auth/approve-login/pending}) and approves
 *       it via the existing {@code /auth/approve-login/{id}/decide} endpoint — no
 *       mobile change.</li>
 *   <li>once the poll shows APPROVED, the client POSTs {@code data.approveSessionId};
 *       the step passes iff that session was approved by EXACTLY the user being
 *       authenticated ({@link ApproveLoginService#isStepApprovedBy}).</li>
 * </ol>
 * No token is minted by the approve here — the user is mid-flow, so the step only
 * advances the MFA session. The match-number requirement provides phishing-resistant
 * device confirmation.
 */
@Component
@RequiredArgsConstructor
public class ApproveLoginVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final ApproveLoginService approveLoginService;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.APPROVE_LOGIN;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        // Phase 1 — issue a step-bound approve session for this user.
        // Body shape MUST mirror WebAuthnVerifySupport: {status:CHALLENGE, data:{...}}
        // — the shared web MfaStepRenderer reads the fields from `response.data.data`.
        if ("challenge".equals(data.get("action"))) {
            Map<String, Object> s = approveLoginService.createStepSession(user.getId());
            return MfaStepResult.challenge(Map.of(
                    "status", "CHALLENGE",
                    "data", Map.of(
                            "approveSessionId", s.get("sessionId"),
                            "sessionId", s.get("sessionId"),
                            "matchNumber", s.get("matchNumber"),
                            "expiresAtEpochSeconds", s.get("expiresAtEpochSeconds")
                    )
            ));
        }

        // Phase 2 — cross-device proof: the SAME user approved it on their phone.
        String approveSessionId = (String) data.get("approveSessionId");
        if (approveSessionId == null || approveSessionId.isBlank()) {
            approveSessionId = (String) data.get("sessionId");
        }
        if (approveSessionId == null || approveSessionId.isBlank()) {
            return MfaStepResult.fail();
        }
        boolean ok = approveLoginService.isStepApprovedBy(approveSessionId, user.getId());
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
