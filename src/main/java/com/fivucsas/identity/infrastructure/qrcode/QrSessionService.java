package com.fivucsas.identity.infrastructure.qrcode;

import com.fivucsas.identity.application.service.UsernamelessLoginFlowService;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Service for managing QR login sessions.
 *
 * QR login flow:
 * 1. Unauthenticated client creates a session (gets sessionId + qrContent)
 * 2. Client displays QR code containing qrContent
 * 3. Authenticated user (on mobile) scans QR and calls approve
 * 4. Original client polls session status and receives tokens when approved
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class QrSessionService {

    private final StringRedisTemplate redisTemplate;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final UsernamelessLoginFlowService usernamelessLoginFlowService;

    private static final Duration SESSION_TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String SESSION_PREFIX = "qr:session:";
    /** Marks a session as a mid-MFA-flow QR FACTOR (not a fresh login). */
    private static final String STEP_BOUND = "stepBound";
    /** The user this step-bound session is issued for (only THEY may satisfy it). */
    private static final String BOUND_USER = "boundUserId";
    /** The user whose phone actually approved the session. */
    private static final String APPROVER_USER = "approverUserId";

    public Map<String, Object> createSession(String platform) {
        String sessionId = UUID.randomUUID().toString();
        byte[] qrBytes = new byte[32];
        RANDOM.nextBytes(qrBytes);
        String qrContent = Base64.getUrlEncoder().withoutPadding().encodeToString(qrBytes);

        long expiresAt = Instant.now().plus(SESSION_TTL).getEpochSecond();

        String key = SESSION_PREFIX + sessionId;
        Map<String, String> sessionData = new HashMap<>();
        sessionData.put("status", "PENDING_SCAN");
        sessionData.put("qrContent", qrContent);
        sessionData.put("platform", platform != null ? platform : "unknown");
        sessionData.put("expiresAt", String.valueOf(expiresAt));

        redisTemplate.opsForHash().putAll(key, sessionData);
        redisTemplate.expire(key, SESSION_TTL);

        log.info("QR session created: {}", sessionId);

        return Map.of(
                "sessionId", sessionId,
                "qrContent", qrContent,
                "status", "PENDING_SCAN",
                "expiresAtEpochSeconds", expiresAt
        );
    }

    public Map<String, Object> getSession(String sessionId) {
        String key = SESSION_PREFIX + sessionId;
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

        if (data.isEmpty()) {
            return Map.of(
                    "sessionId", sessionId,
                    "qrContent", "",
                    "status", "EXPIRED",
                    "message", "Session not found or expired"
            );
        }

        String status = (String) data.get("status");
        String qrContent = (String) data.get("qrContent");
        String expiresAtStr = (String) data.get("expiresAt");
        long expiresAt = expiresAtStr != null ? Long.parseLong(expiresAtStr) : 0;

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);
        response.put("qrContent", qrContent);
        response.put("status", status);
        response.put("expiresAtEpochSeconds", expiresAt);

        if ("APPROVED".equals(status)) {
            String role = (String) data.get("role");
            response.put("role", role);
            // MFA-pending (tenant flow needs more steps): surface the session
            // token instead of access/refresh tokens (task #16 B).
            if ("true".equals(data.get("mfaRequired"))) {
                response.put("mfaRequired", true);
                response.put("mfaSessionToken", data.get("mfaSessionToken"));
                String currentStep = (String) data.get("currentStep");
                String totalSteps = (String) data.get("totalSteps");
                response.put("currentStep", currentStep != null ? Integer.parseInt(currentStep) : 2);
                response.put("totalSteps", totalSteps != null ? Integer.parseInt(totalSteps) : 0);
                // NEXT step's selectable methods (issue #2/#6). Always an array
                // (empty for old sessions written before this field existed).
                response.put("availableMethods", parseAvailableMethods((String) data.get("availableMethods")));
                response.put("message", "Login approved — additional verification required");
            } else {
                String accessToken = (String) data.get("accessToken");
                String refreshToken = (String) data.get("refreshToken");
                String expiresIn = (String) data.get("expiresIn");
                response.put("accessToken", accessToken);
                response.put("refreshToken", refreshToken);
                response.put("expiresIn", expiresIn != null ? Long.parseLong(expiresIn) : 0);
                response.put("message", "Login approved");
            }
        }

        return response;
    }

    /**
     * Parses the stored CSV of AuthMethodType NAME strings back into a list for
     * the poll response. Null/blank (old session or a step with no resolvable
     * methods) yields an empty list — never null — so the wire shape is a stable
     * JSON array (issue #2/#6).
     */
    private static List<String> parseAvailableMethods(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        List<String> methods = new ArrayList<>();
        for (String token : csv.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                methods.add(trimmed);
            }
        }
        return methods;
    }

    public Map<String, Object> approveSession(String sessionId, UUID approverId) {
        String key = SESSION_PREFIX + sessionId;
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

        if (data.isEmpty()) {
            return Map.of(
                    "sessionId", sessionId,
                    "qrContent", "",
                    "status", "EXPIRED",
                    "message", "Session not found or expired"
            );
        }

        String status = (String) data.get("status");
        if (!"PENDING_SCAN".equals(status) && !"PENDING_APPROVAL".equals(status)) {
            return Map.of(
                    "sessionId", sessionId,
                    "qrContent", data.get("qrContent"),
                    "status", status,
                    "message", "Session already " + status.toLowerCase()
            );
        }

        Optional<User> approver = userRepository.findById(approverId);
        if (approver.isEmpty()) {
            return Map.of(
                    "sessionId", sessionId,
                    "qrContent", data.get("qrContent"),
                    "status", "FAILED",
                    "message", "Approver not found"
            );
        }

        // Step-bound session (mid-MFA-flow QR FACTOR, not a fresh login): just
        // record the approver + mark APPROVED. NO token mint / NO login outcome —
        // QrCodeVerifyMfaStepHandler later verifies approverUserId == the user
        // being authenticated (cross-device proof; kills the self-fillable token).
        if ("true".equals(data.get(STEP_BOUND))) {
            Map<String, String> stepUpdates = new HashMap<>();
            stepUpdates.put("status", "APPROVED");
            stepUpdates.put(APPROVER_USER, approverId.toString());
            redisTemplate.opsForHash().putAll(key, stepUpdates);
            redisTemplate.expire(key, Duration.ofMinutes(2));
            log.info("QR step session approved: {} by user {}", sessionId, approverId);
            return Map.of(
                    "sessionId", sessionId,
                    "status", "APPROVED",
                    "message", "Approved"
            );
        }

        User user = approver.get();
        String role = user.getRoleNames().stream()
                .findFirst()
                .orElseGet(() -> user.getUserType() != null ? user.getUserType().name() : "USER");

        Map<String, String> updates = new HashMap<>();
        updates.put("status", "APPROVED");
        updates.put("role", role);

        boolean mfaPending = false;
        if (usernamelessLoginFlowService.isConfigDrivenFor(user)) {
            // Config-driven engine ON for this tenant: bridge the proven QR
            // scan-to-approve (a usernameless Layer-1 factor) INTO the tenant's
            // APP_LOGIN flow (task #16 B). Layer-2+ steps → stash an
            // mfaSessionToken (NOT tokens); the polling client steps up via
            // /api/v1/auth/mfa/step. 1-step / no-flow → mint a real rotating
            // refresh token (tokenGenerator + RefreshTokenService).
            UsernamelessLoginFlowService.FlowOutcome outcome =
                    usernamelessLoginFlowService.continueAfterLayer1(
                            user, AuthMethodType.QR_CODE, "mca", null, null, null);
            mfaPending = outcome.mfaPending();
            if (outcome.mfaPending()) {
                updates.put("mfaRequired", "true");
                updates.put("mfaSessionToken", outcome.mfaSessionToken());
                updates.put("currentStep", String.valueOf(outcome.currentStep()));
                updates.put("totalSteps", String.valueOf(outcome.totalSteps()));
                // NEXT step's selectable methods for the polling web method-picker
                // (issue #2/#6). CSV of AuthMethodType NAME strings; parsed back to a
                // JSON array in getSession. Backward-compatible (absent ⇒ empty array).
                updates.put("availableMethods", String.join(",", outcome.availableMethods()));
            } else {
                updates.put("accessToken", outcome.accessToken());
                updates.put("refreshToken", outcome.refreshToken());
                updates.put("expiresIn", String.valueOf(outcome.expiresIn() / 1000));
            }
            log.info("QR session approved (config-driven): {} by user: {} (mfaPending={})",
                    sessionId, approverId, outcome.mfaPending());
        } else {
            // Legacy path (engine OFF): mint directly, byte-identical to before.
            String accessToken = jwtService.generateAccessToken(user.getEmail());
            long expiresIn = jwtService.getExpirationMillis() / 1000;
            updates.put("accessToken", accessToken);
            updates.put("refreshToken", UUID.randomUUID().toString());
            updates.put("expiresIn", String.valueOf(expiresIn));
            log.info("QR session approved: {} by user: {}", sessionId, approverId);
        }

        redisTemplate.opsForHash().putAll(key, updates);
        redisTemplate.expire(key, Duration.ofMinutes(2));

        return Map.of(
                "sessionId", sessionId,
                "qrContent", data.get("qrContent"),
                "status", "APPROVED",
                "message", mfaPending ? "Login approved — additional verification required"
                        : "Login approved"
        );
    }

    /**
     * Create a STEP-BOUND QR session for a mid-MFA-flow QR FACTOR. Bound to the
     * user currently being authenticated; only THAT user's phone approval
     * satisfies the step (see {@link #isStepApprovedBy}). The phone approves via
     * the SAME {@code POST /auth/qr/session/{id}/approve} endpoint it already uses
     * for QR-login — no mobile change. Reuses the standard poll
     * ({@code GET /auth/qr/session/{id}}). Distinct from {@link #createSession}
     * (a fresh-login session) only by the {@code stepBound}/{@code boundUserId}
     * markers, so {@link #approveSession} mints NO tokens for it.
     */
    public Map<String, Object> createStepSession(UUID boundUserId) {
        String sessionId = UUID.randomUUID().toString();
        byte[] qrBytes = new byte[32];
        RANDOM.nextBytes(qrBytes);
        String qrContent = Base64.getUrlEncoder().withoutPadding().encodeToString(qrBytes);
        long expiresAt = Instant.now().plus(SESSION_TTL).getEpochSecond();

        String key = SESSION_PREFIX + sessionId;
        Map<String, String> sessionData = new HashMap<>();
        sessionData.put("status", "PENDING_SCAN");
        sessionData.put("qrContent", qrContent);
        sessionData.put("platform", "WEB");
        sessionData.put("expiresAt", String.valueOf(expiresAt));
        sessionData.put(STEP_BOUND, "true");
        sessionData.put(BOUND_USER, boundUserId.toString());

        redisTemplate.opsForHash().putAll(key, sessionData);
        redisTemplate.expire(key, SESSION_TTL);

        log.info("QR step session created: {} bound to user {}", sessionId, boundUserId);

        return Map.of(
                "sessionId", sessionId,
                "qrContent", qrContent,
                "status", "PENDING_SCAN",
                "expiresAtEpochSeconds", expiresAt
        );
    }

    /**
     * True iff a STEP-BOUND session was APPROVED by exactly the bound user — i.e.
     * the phone that approved it belongs to the same person being authenticated.
     * This is the cross-device proof that replaces the self-fillable token.
     * Single-use: the session is consumed (deleted) on a successful match so it
     * can't be replayed.
     */
    public boolean isStepApprovedBy(String sessionId, UUID boundUserId) {
        if (sessionId == null || sessionId.isBlank() || boundUserId == null) {
            return false;
        }
        String key = SESSION_PREFIX + sessionId;
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);
        if (data.isEmpty()) {
            return false;
        }
        String want = boundUserId.toString();
        boolean match = "true".equals(data.get(STEP_BOUND))
                && "APPROVED".equals(data.get("status"))
                && want.equals(data.get(APPROVER_USER))
                && want.equals(data.get(BOUND_USER));
        if (match) {
            redisTemplate.delete(key); // single-use
        }
        return match;
    }
}
