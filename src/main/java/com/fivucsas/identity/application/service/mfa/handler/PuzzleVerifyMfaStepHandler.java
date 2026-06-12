package com.fivucsas.identity.application.service.mfa.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Server-authoritative MFA step handler for the {@code PUZZLE} liveness layer
 * (sub-project B, Task 3.3).
 *
 * <p><b>Trust model (the security crux).</b> A PUZZLE step proves LIVENESS by
 * replaying the randomised challenge traces the browser performed and having the
 * SERVER (biometric-processor {@code /liveness/verify-challenge}) re-score each
 * one. The step passes ONLY because the server re-derived the verdict — NEVER
 * because the client claimed completion. Any client-supplied {@code passed} /
 * {@code verified} boolean is IGNORED.
 *
 * <p>The step passes IFF:
 * <ol>
 *   <li>the submitted challenge set satisfies the step's {@code puzzleConfig}
 *       (at least {@code count} challenges, and every challenge's {@code action}
 *       is in {@code allowedChallengeTypes}); AND</li>
 *   <li>EVERY submitted challenge carries a non-empty {@code metrics} payload
 *       (the auth-mode metric requirement — see below); AND</li>
 *   <li>EVERY submitted challenge re-scores to {@code verified:true} at the bio
 *       processor.</li>
 * </ol>
 *
 * <p><b>Fail-closed discipline (mirrors {@link FaceVerifyMfaStepHandler}).</b>
 * Any of the following yields {@link MfaStepResult#fail()} with NO fail-open:
 * a missing/unresolvable {@code puzzleConfig}; fewer challenges than
 * {@code count}; a challenge type not in {@code allowedChallengeTypes}; a
 * challenge missing its {@code action} or with absent/empty {@code metrics}; a
 * bio response missing the {@code verified} field; a {@code verified:false}
 * verdict; a {@code VALIDATION_UNAVAILABLE} soft-pass; or any
 * error/timeout/non-2xx (RuntimeException) from the bio call.
 *
 * <p><b>Auth-mode metric requirement.</b> Bio's {@code /liveness/verify-challenge}
 * is a TRAINING surface: it passes on structural checks (action enum, timestamp
 * monotonicity, duration/confidence floors) ALONE when {@code metrics} are
 * absent (metrics are opt-in there). For the AUTH path that is a hole — a caller
 * could submit a structurally-valid challenge with no real measured metric. This
 * handler therefore REQUIRES a non-empty {@code metrics} object per challenge
 * before forwarding it (handler-side enforcement, coordinated through the same
 * {@link BiometricServicePort#verifyPuzzleChallenge} call). The metric is also
 * forwarded to bio for audit.
 *
 * <p><b>Anti-replay — FLAGGED GAP (SP-C).</b> There is currently NO api-side
 * proxy that issues a server-bound, single-use puzzle session id (the bio
 * {@code active_gesture_liveness_manager} holds sessions in-memory inside the bio
 * service, and {@code /liveness/verify-challenge} is STATELESS — it consults no
 * session). The achievable baseline here is implemented: the server re-scores the
 * ACTUAL per-challenge metric data, which already prevents a forged client pass.
 * Binding the attempt to a server-issued single-use session id (so a captured
 * valid trace cannot be replayed) is the remaining hardening, deferred to
 * sub-project C. See the project report.
 *
 * <p>Reachability is gated upstream: PUZZLE only appears as a selectable factor
 * when {@code PuzzleLayerPolicy} is on (Phase 1), so this handler is unreachable
 * by default.
 */
@Component
@Slf4j
public class PuzzleVerifyMfaStepHandler implements VerifyMfaStepHandler {

    /** Default required-challenge count when {@code puzzleConfig.count} is absent. */
    private static final int DEFAULT_REQUIRED_COUNT = 1;

    private final BiometricServicePort biometricService;
    private final AuthFlowRepositoryPort authFlowRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public PuzzleVerifyMfaStepHandler(BiometricServicePort biometricService,
                                      AuthFlowRepositoryPort authFlowRepository) {
        this.biometricService = biometricService;
        this.authFlowRepository = authFlowRepository;
    }

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.PUZZLE;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        UUID userId = user.getId();

        // 1. Resolve the step's puzzleConfig (count + allowed types). FAIL-CLOSED
        //    if the flow/step/config cannot be resolved — a PUZZLE step with no
        //    resolvable policy must NOT pass on an unconstrained re-score.
        PuzzleConfig config = resolvePuzzleConfig(session);
        if (config == null) {
            log.warn("AUDIT: PUZZLE step rejected — puzzleConfig unresolvable (flowId={}, step={}), userId={}",
                    session.getFlowId(), session.getCurrentStep(), userId);
            return MfaStepResult.fail();
        }

        // 2. Extract the client-performed challenges.
        List<Map<String, Object>> challenges = extractChallenges(data);
        if (challenges.isEmpty()) {
            log.warn("AUDIT: PUZZLE step rejected — no challenges in payload, userId={}", userId);
            return MfaStepResult.fail();
        }

        // 3. Count floor: fewer challenges than puzzleConfig.count → fail (before
        //    any bio side-effect).
        if (challenges.size() < config.count) {
            log.warn("AUDIT: PUZZLE step rejected — {} challenges < required count {}, userId={}",
                    challenges.size(), config.count, userId);
            return MfaStepResult.fail();
        }

        // 4. Validate every challenge structurally (allowed type + present action +
        //    non-empty metrics) BEFORE any bio call, so a malformed/forgeable
        //    payload never triggers a re-score side-effect.
        for (Map<String, Object> challenge : challenges) {
            String action = asString(challenge.get("action"));
            if (action == null || action.isBlank()) {
                log.warn("AUDIT: PUZZLE step rejected — challenge missing `action`, userId={}", userId);
                return MfaStepResult.fail();
            }
            if (!config.allowedChallengeTypes.contains(action.toLowerCase(Locale.ROOT))) {
                log.warn("AUDIT: PUZZLE step rejected — challenge type '{}' not in allowedChallengeTypes {}, userId={}",
                        action, config.allowedChallengeTypes, userId);
                return MfaStepResult.fail();
            }
            // Auth-mode metric requirement: bio passes on structure alone when the
            // metric is absent (opt-in there). For AUTH that is a hole — reject a
            // challenge whose required metric is absent/empty.
            if (!hasNonEmptyMetrics(challenge.get("metrics"))) {
                log.warn("AUDIT: PUZZLE step rejected — challenge '{}' carries no metric (auth requires it), userId={}",
                        action, userId);
                return MfaStepResult.fail();
            }
        }

        // 5. Server-authoritative re-score: EVERY challenge must return verified:true
        //    from the bio processor. Trust ONLY the server `verified` field.
        for (Map<String, Object> challenge : challenges) {
            Map<String, Object> bioResult;
            try {
                bioResult = biometricService.verifyPuzzleChallenge(
                        buildBioRequest(challenge, session, userId));
            } catch (RuntimeException e) {
                // Error / timeout / non-2xx surfaced as a RuntimeException — HARD
                // FAIL (no fail-open). Re-set the interrupt flag if the cause chain
                // carries an InterruptedException (cooperative cancellation).
                if (containsInterrupted(e)) {
                    Thread.currentThread().interrupt();
                }
                log.error("AUDIT: PUZZLE step error — bio re-score threw for action='{}', userId={}",
                        challenge.get("action"), userId, e);
                return MfaStepResult.fail();
            }

            if (!isServerVerified(bioResult, userId)) {
                log.warn("AUDIT: PUZZLE step failed — server re-score rejected action='{}', userId={}",
                        challenge.get("action"), userId);
                return MfaStepResult.fail();
            }
        }

        // Every required challenge re-scored verified=true AND the set satisfied
        // puzzleConfig (count + allowed types) AND each carried a metric.
        return MfaStepResult.ok();
    }

    /**
     * Reads the bio verdict map, trusting ONLY the server {@code verified} field
     * (no client/handler-side fallback — fail-open vector). A missing field, a
     * {@code verified:false}, or a {@code VALIDATION_UNAVAILABLE} soft-pass
     * (which the adapter returns on 404/5xx for the training surface — a HOLE on
     * the auth path) all yield {@code false}.
     */
    private boolean isServerVerified(Map<String, Object> bioResult, UUID userId) {
        if (bioResult == null) {
            log.error("AUDIT: PUZZLE re-score returned null verdict, userId={}", userId);
            return false;
        }
        // The adapter soft-passes (verified=true, reason_code=VALIDATION_UNAVAILABLE)
        // when bio is unreachable/older — acceptable for TRAINING, never for AUTH.
        Object reasonCode = bioResult.get("reason_code");
        if (reasonCode instanceof String rc && "VALIDATION_UNAVAILABLE".equals(rc)) {
            log.warn("AUDIT: PUZZLE re-score soft-pass (bio unavailable) rejected on auth path, userId={}", userId);
            return false;
        }
        Object verifiedClaim = bioResult.get("verified");
        if (verifiedClaim == null) {
            log.error("AUDIT: PUZZLE re-score missing `verified` field — rejecting, userId={}, keys={}",
                    userId, bioResult.keySet());
            return false;
        }
        return Boolean.TRUE.equals(verifiedClaim)
                || "true".equalsIgnoreCase(String.valueOf(verifiedClaim));
    }

    /**
     * Builds the snake_case {@code VerifyChallengeRequest} body the bio
     * {@code /liveness/verify-challenge} route expects, stamping the
     * server-resolved user/tenant (never a client-supplied identity). Accepts
     * either camelCase or snake_case timestamp keys from the client payload.
     */
    private Map<String, Object> buildBioRequest(Map<String, Object> challenge,
                                                MfaSession session, UUID userId) {
        Map<String, Object> req = new HashMap<>();
        req.put("action", asString(challenge.get("action")));
        req.put("start_timestamp_ms", firstNumber(challenge, "start_timestamp_ms", "startTimestampMs"));
        req.put("end_timestamp_ms", firstNumber(challenge, "end_timestamp_ms", "endTimestampMs"));
        req.put("confidence", firstNumber(challenge, "confidence"));
        req.put("user_id", userId.toString());
        if (session.getTenantId() != null) {
            req.put("tenant_id", session.getTenantId().toString());
        }
        Object metrics = challenge.get("metrics");
        if (metrics instanceof Map<?, ?> m) {
            req.put("metrics", m);
        }
        return req;
    }

    /**
     * Resolves the {@link PuzzleConfig} from the CURRENT step's persisted
     * {@code config} JSONB blob (the same blob Phase 2.4 surfaces in
     * login-config). Returns null when the flow/step/blob cannot be resolved or
     * does not carry a {@code puzzleConfig} object → caller fails closed.
     */
    private PuzzleConfig resolvePuzzleConfig(MfaSession session) {
        AuthFlow flow = authFlowRepository.findById(session.getFlowId()).orElse(null);
        if (flow == null || flow.getSteps() == null) {
            return null;
        }
        int currentStepOrder = session.getCurrentStep();
        AuthFlowStep step = flow.getSteps().stream()
                .filter(s -> s != null && s.getStepOrder() == currentStepOrder)
                .findFirst()
                .orElse(null);
        if (step == null) {
            return null;
        }
        return parsePuzzleConfig(step.getConfig());
    }

    /**
     * Parses {@code {"puzzleConfig":{"count":N,"allowedChallengeTypes":[...]}}}.
     * Returns null when the blob is blank, unparseable, or has no
     * {@code puzzleConfig} object, OR when {@code allowedChallengeTypes} is empty
     * (an empty allow-list cannot satisfy any challenge → fail-closed rather than
     * accept-everything). Challenge type tokens are lower-cased to match the bio
     * enum string values.
     */
    private PuzzleConfig parsePuzzleConfig(String configJson) {
        if (configJson == null || configJson.isBlank()) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode puzzle = root.get("puzzleConfig");
            if (puzzle == null || !puzzle.isObject()) {
                return null;
            }
            JsonNode countNode = puzzle.get("count");
            int count = countNode != null && countNode.isInt()
                    ? countNode.asInt() : DEFAULT_REQUIRED_COUNT;
            if (count < 1) {
                count = DEFAULT_REQUIRED_COUNT;
            }
            Set<String> allowed = new LinkedHashSet<>();
            JsonNode typesNode = puzzle.get("allowedChallengeTypes");
            if (typesNode != null && typesNode.isArray()) {
                for (JsonNode t : typesNode) {
                    String v = t.asText(null);
                    if (v != null && !v.isBlank()) {
                        allowed.add(v.trim().toLowerCase(Locale.ROOT));
                    }
                }
            }
            if (allowed.isEmpty()) {
                // No allow-list → nothing can satisfy the step. Fail closed.
                return null;
            }
            return new PuzzleConfig(count, allowed);
        } catch (Exception e) {
            log.warn("PUZZLE step config unparseable as JSON — failing closed: {}", e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> extractChallenges(Map<String, Object> data) {
        if (data == null) {
            return List.of();
        }
        Object raw = data.get("challenges");
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> out = new java.util.ArrayList<>(list.size());
        for (Object el : list) {
            if (el instanceof Map<?, ?> m) {
                out.add((Map<String, Object>) m);
            } else {
                // A non-object element means a malformed payload — drop it; the
                // count floor / structural checks will then reject as needed.
                return List.of();
            }
        }
        return out;
    }

    private static boolean hasNonEmptyMetrics(Object metrics) {
        return metrics instanceof Map<?, ?> m && !m.isEmpty();
    }

    private static String asString(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    /** Returns the first present numeric value among {@code keys}, else null. */
    private static Object firstNumber(Map<String, Object> challenge, String... keys) {
        for (String k : keys) {
            Object v = challenge.get(k);
            if (v instanceof Number) {
                return v;
            }
        }
        return null;
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

    /** Parsed, validated {@code puzzleConfig}: required count + allowed challenge types. */
    private record PuzzleConfig(int count, Set<String> allowedChallengeTypes) {
        private PuzzleConfig(int count, Set<String> allowedChallengeTypes) {
            this.count = count;
            this.allowedChallengeTypes = allowedChallengeTypes;
        }
    }
}
