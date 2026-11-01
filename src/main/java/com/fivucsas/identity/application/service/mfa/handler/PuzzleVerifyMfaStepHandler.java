package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.port.output.PuzzleSessionGuardPort;
import com.fivucsas.identity.application.service.ClientSideEmbeddingPolicy;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Server-authoritative MFA step handler for the {@code PUZZLE} liveness layer
 * (CV-2 of the puzzle-as-login convergence — canonical contract in
 * {@code docs/superpowers/plans/2026-06-12-puzzle-session-convergence.md}), with
 * the optional SP-B identity-binding branch (plan
 * {@code docs/superpowers/plans/2026-06-11-client-side-embedding-B.md} Task 5.2;
 * spec §3.1).
 *
 * <p><b>Trust model (the security crux).</b> A PUZZLE step proves LIVENESS via a
 * server-issued, single-use, anti-replay puzzle SESSION whose scoring state lives
 * entirely in the biometric-processor. The browser drives the session DURING the
 * MFA step through the MFA-flow proxy ({@code POST /auth/mfa/puzzle/session} +
 * {@code .../{sessionId}/challenge}); at the gate the client sends the opaque
 * {@code puzzle_session_id} (and, when identity-binding is on, the 512-float
 * {@code embedding} extracted from the SAME live capture). This handler asks bio
 * for the AUTHORITATIVE verdict
 * ({@code POST /api/v1/liveness/puzzle-session/{id}/verdict}) and passes ONLY on
 * {@code verified:true}. It trusts NOTHING else in {@code data} — no metrics, no
 * client "passed"/"verified" booleans, no re-score at identity.
 *
 * <p><b>Identity-binding (SP-B, additive, DOUBLE-gated, fail-closed).</b> A PUZZLE
 * step proves LIVENESS only. When the tenant admin turns ON the step-config flag
 * {@code puzzleConfig.alsoMatchFaceIdentity} AND the SP-A client-side-embedding
 * policy is enabled for the tenant, the SAME step ALSO matches FACE IDENTITY: the
 * client's live-capture {@code embedding} is forwarded to bio's
 * {@code POST /verify-embedding} (server-owned pgvector cosine match). The step
 * passes ONLY if liveness {@code verified:true} AND (binding NOT required OR
 * identity {@code verified:true}). Binding is double-gated: the auth-flow config
 * flag chooses to bind, AND the SP-A feature flag must be on for the embedding
 * path to exist at all — either being off means liveness-only (the SP-A flag
 * double-gates so the binding cannot accidentally engage during a partial
 * rollout). Canonical rule honoured: PUZZLE alone (binding off) proves LIVENESS;
 * identity comes ONLY from the embedding match.
 *
 * <p><b>Fail-closed when binding-required-but-no-embedding.</b> If binding is
 * required and {@code data.embedding} is absent or not a 512-float vector, the
 * step FAILS (never a liveness-only pass) — an attacker cannot drop the embedding
 * to downgrade a bound step to liveness-only.
 *
 * <p>This SUPERSEDES the earlier interim where the handler re-scored the raw
 * per-challenge metrics at identity (bio {@code /liveness/verify-challenge} is
 * stateless, so a captured valid trace was replayable). The session is consumed
 * on the verdict call (single-use) and is owner-bound to {@code user_id +
 * tenant_id}, so a captured trace cannot be replayed: a replay needs a fresh
 * server-issued session with its own random challenges.
 *
 * <p><b>Owner binding is SERVER-stamped (never client-supplied).</b> BOTH the
 * verdict call and the embedding-match call are made with the {@code user_id} and
 * {@code tenant_id} resolved from the in-progress MFA session
 * ({@code user.getId()} / {@code session.getTenantId()}), NOT any identity carried
 * in {@code data}. bio cross-checks the verdict owner against the session it
 * recorded at CREATE; the embedding match is run against the SERVER user's
 * enrolled template, so a session/embedding issued for A can never verdict/match B.
 *
 * <p><b>Fail-closed discipline (mirrors {@link FaceVerifyMfaStepHandler}).</b>
 * Any of the following yields {@link MfaStepResult#fail()} with NO fail-open:
 * a missing/blank {@code puzzle_session_id}; a missing server tenant on the MFA
 * session; a bio response missing the {@code verified} field; a
 * {@code verified:false} verdict; a fail-closed error map from the adapter
 * (404 unknown/expired/consumed, other non-2xx, transport error); any
 * RuntimeException from a bio call; or — when binding is required — a missing /
 * wrong-length embedding or an identity match that is not {@code verified:true}.
 *
 * <p><b>Puzzle contract v2 binding-frame consistency check (version handshake,
 * fail-closed).</b> When binding is required, the verdict also carries the
 * client-declared {@code binding_frame}. bio v2 checks it ONLY against the
 * client's own trace: it does NOT tie the matched embedding to the live capture,
 * and a modified client can pass it (real binding needs server-observed image
 * data or attested capture). The step then passes only if bio answers
 * {@code binding_checked:true} — unless the identity side recorded at CREATE that
 * bio advertised the legacy v1 contract for this session (bio flag OFF), in which
 * case the legacy behaviour is kept. A malformed binding frame (or a missing one
 * on a non-v1 session) fails in identity and the bio session is CONSUMED via a
 * plain verdict call, so it can never be reused.
 *
 * <p>Reachability is gated upstream: PUZZLE only appears as a selectable factor
 * when {@code PuzzleLayerPolicy} is on (Phase 1), so this handler is unreachable
 * by default; the identity-binding branch is additionally gated by
 * {@code ClientSideEmbeddingPolicy}.
 */
@Component
@Slf4j
public class PuzzleVerifyMfaStepHandler implements VerifyMfaStepHandler {

    /** Facenet512 produces a 512-dimension L2-normalized embedding (spec §3.1). */
    private static final int EMBEDDING_DIM = 512;

    private final BiometricServicePort biometricService;
    // SP-B identity-binding dependencies (additive). The auth-flow repo lets the
    // handler read the CURRENT step's `puzzleConfig.alsoMatchFaceIdentity`; the
    // policy is the SP-A client-side-embedding feature flag that double-gates the
    // binding so it cannot engage during a partial rollout.
    private final AuthFlowRepositoryPort authFlowRepository;
    private final ClientSideEmbeddingPolicy clientSideEmbeddingPolicy;
    // Puzzle contract v2 (S5): the trace contract bio advertised at CREATE.
    private final PuzzleSessionGuardPort puzzleSessionGuard;
    // Local, thread-safe mapper to parse the step `config` JSONB blob — mirrors
    // AuthController.puzzleObjectMapper (no shared bean needed, parse is read-only).
    private final ObjectMapper configObjectMapper = new ObjectMapper();

    public PuzzleVerifyMfaStepHandler(BiometricServicePort biometricService,
                                      AuthFlowRepositoryPort authFlowRepository,
                                      ClientSideEmbeddingPolicy clientSideEmbeddingPolicy,
                                      PuzzleSessionGuardPort puzzleSessionGuard) {
        this.biometricService = biometricService;
        this.authFlowRepository = authFlowRepository;
        this.clientSideEmbeddingPolicy = clientSideEmbeddingPolicy;
        this.puzzleSessionGuard = puzzleSessionGuard;
    }

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.PUZZLE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        UUID userId = user.getId();

        // 1. The client sends the opaque puzzle_session_id (and, when binding is
        //    on, the live-capture embedding). Any client metrics/verdicts/
        //    identities in `data` are IGNORED — bio holds all scoring state. A
        //    missing/blank id is a hard fail.
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

        // Identity-binding requirement is resolved up front (server config only)
        // so the liveness verdict can carry the binding frame.
        boolean bindingRequired = isBindingRequired(session, tenantId);

        // Contract v2 handshake inputs (only relevant when binding is required).
        // legacyV1 = the identity side recorded at CREATE that bio advertised v1
        // (bio flag OFF): keep the legacy behaviour. Unknown ⇒ strict.
        boolean legacyV1 = false;
        Map<String, Object> bindingFrame = null;
        if (bindingRequired) {
            legacyV1 = recordedContract(sessionId)
                    .map(PuzzleSessionGuardPort.CONTRACT_V1::equals)
                    .orElse(false);
            Object rawFrame = data.get("binding_frame");
            bindingFrame = extractBindingFrame(rawFrame);
            boolean malformed = rawFrame != null && bindingFrame == null;
            boolean missingOnV2 = rawFrame == null && !legacyV1;
            if (malformed || missingOnV2) {
                // S6: fail in identity AND consume the bio session (plain verdict,
                // result ignored) so a rejected attempt cannot leave it live.
                log.warn("AUDIT: PUZZLE step failed — binding frame {} (fail-closed, bio session consumed), userId={}",
                        malformed ? "malformed" : "missing", userId);
                consumeQuietly(sessionId, userId, tenantId);
                return MfaStepResult.fail();
            }
        }

        // 3. LIVENESS gate (first): authoritative verdict from bio (consumes the
        //    single-use session). Pass the SERVER user_id + tenant_id, never any
        //    client value. When identity-binding is required, also forward the
        //    client-declared binding frame (the landmarks + timestamp of the frame
        //    the embedding came from); under bio puzzle contract v2 the verdict
        //    then fails unless that frame lies inside a verified face-challenge
        //    window of the SAME session with consistent geometry (the
        //    binding-frame consistency check; client data checked against client
        //    data, not proof of capture provenance).
        Map<String, Object> verdict;
        try {
            verdict = bindingRequired
                    ? biometricService.getPuzzleVerdictWithBinding(sessionId, userId, tenantId, bindingFrame)
                    : biometricService.getPuzzleVerdict(sessionId, userId, tenantId);
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

        if (!isServerVerified(verdict, userId, "verdict")) {
            log.warn("AUDIT: PUZZLE step failed — bio verdict not verified, userId={}", userId);
            return MfaStepResult.fail();
        }

        // 4. IDENTITY-BINDING gate (SP-B, additive). Required iff the step's
        //    puzzleConfig.alsoMatchFaceIdentity is true AND the SP-A
        //    client-side-embedding policy is enabled for the tenant (double-gate).
        if (!bindingRequired) {
            // Binding off → PUZZLE proves LIVENESS only (canonical rule). Pass on
            // the liveness verdict alone.
            return MfaStepResult.ok();
        }

        // S5 version handshake: a binding-required step on a non-v1 session passes
        // only when bio confirms it actually evaluated the binding-frame check.
        // Guards against a bio that ignores the binding (old build / flag skew).
        if (!legacyV1 && !Boolean.TRUE.equals(verdict.get("binding_checked"))) {
            log.warn("AUDIT: PUZZLE step failed — binding required but bio verdict lacks "
                    + "binding_checked=true (fail-closed), userId={}", userId);
            return MfaStepResult.fail();
        }

        // Binding required: the live-capture embedding MUST be present and a
        // 512-float vector — fail closed otherwise (NOT a liveness-only pass).
        List<Double> embedding = extractEmbedding(data.get("embedding"));
        if (embedding == null || embedding.size() != EMBEDDING_DIM) {
            log.warn("AUDIT: PUZZLE step failed — identity-binding required but embedding "
                            + "absent/wrong-length (fail-closed), userId={}, len={}",
                    userId, embedding == null ? null : embedding.size());
            return MfaStepResult.fail();
        }

        // Run the server-owned pgvector identity match against the SERVER user's
        // enrolled template (server-stamped user_id + tenant_id, never client).
        Map<String, Object> identityResult;
        try {
            identityResult = biometricService.verifyEmbedding(tenantId.toString(), userId, embedding);
        } catch (RuntimeException e) {
            if (containsInterrupted(e)) {
                Thread.currentThread().interrupt();
            }
            log.error("AUDIT: PUZZLE step error — bio embedding-match threw (binding), userId={}", userId, e);
            return MfaStepResult.fail();
        }

        if (!isServerVerified(identityResult, userId, "embedding-match")) {
            log.warn("AUDIT: PUZZLE step failed — identity-binding embedding match not verified, userId={}", userId);
            return MfaStepResult.fail();
        }

        // Pass: liveness verified:true AND identity verified:true.
        return MfaStepResult.ok();
    }

    /**
     * Determines whether identity-binding is REQUIRED for this step: BOTH the
     * step-config flag {@code puzzleConfig.alsoMatchFaceIdentity == true} AND the
     * SP-A {@code ClientSideEmbeddingPolicy} enabled for the tenant. Either off ⇒
     * liveness-only (the SP-A flag double-gates the binding).
     */
    private boolean isBindingRequired(MfaSession session, UUID tenantId) {
        if (!clientSideEmbeddingPolicy.isEnabledForTenant(tenantId)) {
            return false;
        }
        return readAlsoMatchFaceIdentity(session);
    }

    /**
     * Reads {@code puzzleConfig.alsoMatchFaceIdentity} from the CURRENT step's
     * persisted {@code config} JSONB blob (Task 2.4 round-trip — the same blob the
     * login-config response surfaces). Defaults to {@code false} (no binding) when
     * the flow/step/blob/field cannot be resolved or is unparseable, so a missing
     * config never silently engages a stronger gate — but ALSO never weakens the
     * already-passed liveness gate (this only controls whether the EXTRA identity
     * gate runs). Mirrors {@code AuthController.resolvePuzzleStepPolicy}.
     */
    private boolean readAlsoMatchFaceIdentity(MfaSession session) {
        AuthFlow flow = authFlowRepository.findById(session.getFlowId()).orElse(null);
        if (flow == null || flow.getSteps() == null) {
            return false;
        }
        int currentStepOrder = session.getCurrentStep();
        AuthFlowStep step = flow.getSteps().stream()
                .filter(s -> s != null && s.getStepOrder() == currentStepOrder)
                .findFirst()
                .orElse(null);
        if (step == null) {
            return false;
        }
        String configJson = step.getConfig();
        if (configJson == null || configJson.isBlank()) {
            return false;
        }
        try {
            JsonNode root = configObjectMapper.readTree(configJson);
            JsonNode puzzle = root.get("puzzleConfig");
            if (puzzle == null || !puzzle.isObject()) {
                return false;
            }
            JsonNode flag = puzzle.get("alsoMatchFaceIdentity");
            return flag != null && flag.asBoolean(false);
        } catch (Exception e) {
            log.warn("PUZZLE step config unparseable as JSON — identity-binding treated as off: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Reads a bio verdict/match map, trusting ONLY the server {@code verified}
     * field. A null map, a fail-closed adapter error map (carries
     * {@code success=false} and NO {@code verified} key — 404/non-2xx/transport),
     * a missing {@code verified} field, or a {@code verified:false} all yield
     * {@code false}.
     */
    private boolean isServerVerified(Map<String, Object> result, UUID userId, String label) {
        if (result == null) {
            log.error("AUDIT: PUZZLE {} returned null, userId={}", label, userId);
            return false;
        }
        Object verifiedClaim = result.get("verified");
        if (verifiedClaim == null) {
            // Includes the adapter's fail-closed {success:false, message} error map
            // (404 unknown/expired/consumed, other non-2xx, transport failure):
            // no `verified` key ⇒ reject.
            log.error("AUDIT: PUZZLE {} missing `verified` field — rejecting, userId={}, keys={}",
                    label, userId, result.keySet());
            return false;
        }
        return Boolean.TRUE.equals(verifiedClaim)
                || "true".equalsIgnoreCase(String.valueOf(verifiedClaim));
    }

    // ---- Puzzle contract v2 binding frame (bounds mirror bio's schema) ----

    /** Face trace frame: 32 landmarks × (x, y, z) ints (bio {@code _FACE_TRACE_INTS}). */
    static final int BINDING_FRAME_INTS = 32 * 3;
    /** |coordinate| bound in 1e-4 units (bio {@code _TRACE_COORD_ABS_MAX}). */
    static final long COORD_ABS_MAX = 20_000L;
    /** Timestamp upper bound in ms (bio {@code le=2**53}). */
    static final long T_MAX = 1L << 53;
    /** Frame dimension bounds in px (bio {@code ge=64, le=8192}), checked when present. */
    static final int FRAME_DIM_MIN = 64;
    static final int FRAME_DIM_MAX = 8192;

    /**
     * Validates the client-declared binding frame ({@code {"t": <ms>, "f": [96 ints]}})
     * with the SAME bounds bio applies (|coord| ≤ 20000, 0 ≤ t ≤ 2^53, 96 ints for a
     * face frame — a 63-int (21×3) hand frame is rejected; optional {@code frame_width}/{@code frame_height} within 64..8192
     * when supplied, though they are not forwarded — bio uses the trace's own
     * dimensions) and returns a sanitized copy holding ONLY {@code t} and {@code f},
     * or {@code null} when absent or malformed. A malformed frame therefore fails in
     * identity instead of reaching bio (S6).
     */
    static Map<String, Object> extractBindingFrame(Object raw) {
        if (!(raw instanceof Map<?, ?> map)) {
            return null;
        }
        Object t = map.get("t");
        Object f = map.get("f");
        if (!(t instanceof Number tn) || !isIntegral(tn)) {
            return null;
        }
        long tv = tn.longValue();
        if (tv < 0 || tv > T_MAX) {
            return null;
        }
        if (!dimensionOk(map.get("frame_width")) || !dimensionOk(map.get("frame_height"))) {
            return null;
        }
        if (!(f instanceof List<?> list) || list.size() != BINDING_FRAME_INTS) {
            return null;
        }
        List<Long> coords = new ArrayList<>(BINDING_FRAME_INTS);
        for (Object v : list) {
            if (!(v instanceof Number n) || !isIntegral(n)) {
                return null;
            }
            long c = n.longValue();
            if (c > COORD_ABS_MAX || c < -COORD_ABS_MAX) {
                return null;
            }
            coords.add(c);
        }
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put("t", tv);
        out.put("f", coords);
        return out;
    }

    private static boolean isIntegral(Number n) {
        double d = n.doubleValue();
        return Double.isFinite(d) && d == Math.rint(d);
    }

    /** Absent is fine; when present it must be an integral 64..8192. */
    private static boolean dimensionOk(Object v) {
        if (v == null) {
            return true;
        }
        if (!(v instanceof Number n) || !isIntegral(n)) {
            return false;
        }
        long d = n.longValue();
        return d >= FRAME_DIM_MIN && d <= FRAME_DIM_MAX;
    }

    /** Trace contract recorded at CREATE for this bio session (empty = unknown). */
    private Optional<String> recordedContract(String sessionId) {
        try {
            Optional<String> c = puzzleSessionGuard.traceContractFor(sessionId);
            return c == null ? Optional.empty() : c;
        } catch (RuntimeException e) {
            log.warn("PUZZLE trace-contract lookup failed — treating as unknown (strict): {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Consumes the bio session via a plain verdict call and ignores the result
     * (the step has already failed in identity). bio consumes a live session on
     * any verdict, so a rejected attempt cannot leave it reusable.
     */
    private void consumeQuietly(String sessionId, UUID userId, UUID tenantId) {
        try {
            biometricService.getPuzzleVerdict(sessionId, userId, tenantId);
        } catch (RuntimeException e) {
            if (containsInterrupted(e)) {
                Thread.currentThread().interrupt();
            }
            log.warn("PUZZLE session consume after binding-frame rejection failed (session expires by TTL): {}",
                    e.getMessage());
        }
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

    /**
     * Coerces the {@code embedding} payload field (a JSON array deserialized into a
     * {@code List<?>} of {@link Number}, or absent) into a {@code List<Double>}.
     * Returns null when the value is absent or not a list; a non-numeric element
     * makes the WHOLE embedding invalid (null) so a malformed payload fails closed
     * rather than sending garbage to bio. The 512-length check is applied by the
     * caller. Mirrors {@code FaceVerifyMfaStepHandler.extractEmbedding}.
     */
    private static List<Double> extractEmbedding(Object raw) {
        if (!(raw instanceof List<?> list)) {
            return null;
        }
        List<Double> out = new ArrayList<>(list.size());
        for (Object el : list) {
            if (el instanceof Number n) {
                out.add(n.doubleValue());
            } else {
                return null; // malformed element → not a usable embedding
            }
        }
        return out;
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
