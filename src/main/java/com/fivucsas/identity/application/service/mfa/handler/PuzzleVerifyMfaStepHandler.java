package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

/**
 * Server-authoritative MFA step handler for the {@code PUZZLE} liveness layer
 * (CV-2 of the puzzle-as-login convergence — canonical contract in
 * {@code docs/superpowers/plans/2026-06-12-puzzle-session-convergence.md}).
 *
 * <p><b>Trust model (the security crux).</b> A PUZZLE step proves LIVENESS via a
 * server-issued, single-use, anti-replay puzzle SESSION whose scoring state lives
 * entirely in the biometric-processor. The browser drives the session DURING the
 * MFA step through the MFA-flow proxy ({@code POST /auth/mfa/puzzle/session} +
 * {@code .../{sessionId}/challenge}); at the gate the client sends ONLY the opaque
 * {@code puzzle_session_id}. This handler asks bio for the AUTHORITATIVE verdict
 * ({@code POST /api/v1/liveness/puzzle-session/{id}/verdict}) and passes ONLY on
 * {@code verified:true}. It trusts NOTHING else in {@code data} — no metrics, no
 * client "passed"/"verified" booleans, no re-score at identity.
 *
 * <p>This SUPERSEDES the earlier interim where the handler re-scored the raw
 * per-challenge metrics at identity (bio {@code /liveness/verify-challenge} is
 * stateless, so a captured valid trace was replayable). The session is consumed
 * on the verdict call (single-use) and is owner-bound to {@code user_id +
 * tenant_id}, so a captured trace cannot be replayed: a replay needs a fresh
 * server-issued session with its own random challenges.
 *
 * <p><b>Owner binding is SERVER-stamped (never client-supplied).</b> The verdict
 * is requested with the {@code user_id} and {@code tenant_id} resolved from the
 * in-progress MFA session ({@code user.getId()} / {@code session.getTenantId()}),
 * NOT any identity carried in {@code data}. bio cross-checks these against the
 * session owner it recorded at CREATE, so a session issued for A can never
 * verdict B.
 *
 * <p><b>Fail-closed discipline (mirrors {@link FaceVerifyMfaStepHandler}).</b>
 * Any of the following yields {@link MfaStepResult#fail()} with NO fail-open:
 * a missing/blank {@code puzzle_session_id}; a missing server tenant on the MFA
 * session; a bio response missing the {@code verified} field; a
 * {@code verified:false} verdict; a fail-closed error map from the adapter
 * (404 unknown/expired/consumed, other non-2xx, transport error); or any
 * RuntimeException from the bio call.
 *
 * <p>Reachability is gated upstream: PUZZLE only appears as a selectable factor
 * when {@code PuzzleLayerPolicy} is on (Phase 1), so this handler is unreachable
 * by default.
 */
@Component
@Slf4j
public class PuzzleVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final BiometricServicePort biometricService;

    public PuzzleVerifyMfaStepHandler(BiometricServicePort biometricService) {
        this.biometricService = biometricService;
    }

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.PUZZLE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        UUID userId = user.getId();

        // 1. The client sends ONLY the opaque puzzle_session_id. Anything else in
        //    `data` (metrics, verdicts, identities) is IGNORED — bio holds all
        //    scoring state. A missing/blank id is a hard fail.
        String sessionId = extractSessionId(data);
        if (sessionId == null || sessionId.isBlank()) {
            log.warn("AUDIT: PUZZLE step rejected — no puzzle_session_id in payload, userId={}", userId);
            return MfaStepResult.fail();
        }

        // 2. Owner identity is SERVER-stamped from the MFA session, never the
        //    client. A PUZZLE step with no resolvable tenant cannot be owner-bound
        //    to the bio session → fail closed rather than verdict an unbound id.
        UUID tenantId = session.getTenantId();
        if (tenantId == null) {
            log.warn("AUDIT: PUZZLE step rejected — MFA session carries no tenant (cannot owner-bind verdict), userId={}",
                    userId);
            return MfaStepResult.fail();
        }

        // 3. Authoritative verdict from bio (consumes the single-use session).
        //    Pass the SERVER user_id + tenant_id, never any client value.
        Map<String, Object> verdict;
        try {
            verdict = biometricService.getPuzzleVerdict(sessionId, userId, tenantId);
        } catch (RuntimeException e) {
            // Error / timeout / unexpected — HARD FAIL (no fail-open). Re-set the
            // interrupt flag if the cause chain carries an InterruptedException.
            if (containsInterrupted(e)) {
                Thread.currentThread().interrupt();
            }
            log.error("AUDIT: PUZZLE step error — bio verdict threw, sessionId-present={}, userId={}",
                    true, userId, e);
            return MfaStepResult.fail();
        }

        if (!isServerVerified(verdict, userId)) {
            log.warn("AUDIT: PUZZLE step failed — bio verdict not verified, userId={}", userId);
            return MfaStepResult.fail();
        }

        return MfaStepResult.ok();
    }

    /**
     * Reads the bio verdict map, trusting ONLY the server {@code verified} field.
     * A null map, a fail-closed adapter error map (carries {@code success=false}
     * and NO {@code verified} key — 404/non-2xx/transport), a missing
     * {@code verified} field, or a {@code verified:false} all yield {@code false}.
     */
    private boolean isServerVerified(Map<String, Object> verdict, UUID userId) {
        if (verdict == null) {
            log.error("AUDIT: PUZZLE verdict returned null, userId={}", userId);
            return false;
        }
        Object verifiedClaim = verdict.get("verified");
        if (verifiedClaim == null) {
            // Includes the adapter's fail-closed {success:false, message} error map
            // (404 unknown/expired/consumed, other non-2xx, transport failure):
            // no `verified` key ⇒ reject.
            log.error("AUDIT: PUZZLE verdict missing `verified` field — rejecting, userId={}, keys={}",
                    userId, verdict.keySet());
            return false;
        }
        return Boolean.TRUE.equals(verifiedClaim)
                || "true".equalsIgnoreCase(String.valueOf(verifiedClaim));
    }

    /** Extracts the opaque session id, accepting snake_case or camelCase. */
    private static String extractSessionId(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        Object raw = data.get("puzzle_session_id");
        if (raw == null) {
            raw = data.get("puzzleSessionId");
        }
        return raw == null ? null : String.valueOf(raw);
    }

    private static boolean containsInterrupted(Throwable t) {
        while (t != null) {
            if (t instanceof InterruptedException) {
                return true;
            }
            t = t.getCause();
        }
        return false;
    }
}
