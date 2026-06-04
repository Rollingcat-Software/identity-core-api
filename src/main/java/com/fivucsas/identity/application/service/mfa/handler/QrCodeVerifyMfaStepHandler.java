package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.qrcode.QrCodeService;
import com.fivucsas.identity.infrastructure.qrcode.QrSessionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Verifies a {@link AuthMethodType#QR_CODE} step.
 *
 * <p><b>Cross-device session approval (the real factor).</b> Two-phase, like the
 * WebAuthn handlers:
 * <ol>
 *   <li>client POSTs {@code data.action="challenge"} → we create a STEP-BOUND
 *       {@link QrSessionService} session for THIS user and return its
 *       {@code qrSessionId}. The web renders the session QR + polls; the user's
 *       already-signed-in phone scans + approves it via the existing
 *       {@code /auth/qr/session/{id}/approve} endpoint (no mobile change).</li>
 *   <li>once the poll shows APPROVED, the client POSTs {@code data.qrSessionId};
 *       the step passes iff that session was approved by EXACTLY the user being
 *       authenticated ({@link QrSessionService#isStepApprovedBy}).</li>
 * </ol>
 * This is genuine cross-device proof — there is no token to type, so the old
 * "fill the field with your own token and pass" cheat is gone.
 *
 * <p><b>Legacy token path.</b> Kept for backward compatibility (older web
 * bundles / direct API callers that still POST {@code data.token}) and gated by
 * {@code fivucsas.qr.session-approval-required} (default {@code false}). Flip it
 * {@code true} (env {@code FIVUCSAS_QR_SESSION_APPROVAL_REQUIRED=true}, no
 * redeploy) to REJECT the legacy token entirely once every client renders the
 * session QR — fully closing the cheat at the API layer.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class QrCodeVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final QrCodeService qrCodeService;
    private final QrSessionService qrSessionService;

    /** When true, the self-fillable legacy token is rejected — session approval only. */
    @Value("${fivucsas.qr.session-approval-required:false}")
    private boolean sessionApprovalRequired;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.QR_CODE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        // Phase 1 — issue a step-bound session QR for this user.
        // Body shape MUST mirror WebAuthnVerifySupport: {status:CHALLENGE, data:{...}}
        // — the shared web MfaStepRenderer reads the fields from `response.data.data`.
        if ("challenge".equals(data.get("action"))) {
            Map<String, Object> s = qrSessionService.createStepSession(user.getId());
            return MfaStepResult.challenge(Map.of(
                    "status", "CHALLENGE",
                    "data", Map.of(
                            "qrSessionId", s.get("sessionId"),
                            "sessionId", s.get("sessionId"),
                            "expiresAtEpochSeconds", s.get("expiresAtEpochSeconds"),
                            "sessionApproval", true
                    )
            ));
        }

        // Phase 2 — cross-device proof: the SAME user approved the session on
        // their phone. This path always wins when a session id is supplied,
        // regardless of the flag, so the new web is never cheatable.
        String qrSessionId = (String) data.get("qrSessionId");
        if (qrSessionId == null || qrSessionId.isBlank()) {
            qrSessionId = (String) data.get("sessionId");
        }
        if (qrSessionId != null && !qrSessionId.isBlank()) {
            boolean ok = qrSessionService.isStepApprovedBy(qrSessionId, user.getId());
            return ok ? MfaStepResult.ok() : MfaStepResult.fail();
        }

        // Legacy self-fillable token. Rejected once session approval is required.
        if (sessionApprovalRequired) {
            log.debug("QR step: legacy token rejected (session-approval-required) for user {}", user.getId());
            return MfaStepResult.fail();
        }
        String token = (String) data.get("token");
        if (token == null || token.isBlank()) {
            return MfaStepResult.fail();
        }
        boolean ok = qrCodeService.validateToken(token, user.getId());
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }
}
