package com.fivucsas.identity.infrastructure.approvelogin;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.application.service.UsernamelessLoginFlowService;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * No-Firebase number-matching approve-login.
 *
 * <p>Mirrors {@link com.fivucsas.identity.infrastructure.qrcode.QrSessionService}
 * (Redis-backed session + TTL + polling + token-mint) but instead of a QR code
 * the cross-device challenge is a two-digit match number, the way Google /
 * Microsoft number-matching prompts work:
 *
 * <ol>
 *   <li>An unauthenticated client posts the account {@code email}; we look the
 *       user up, create a PENDING session, and return a two-digit
 *       {@code matchNumber} that the client displays.</li>
 *   <li>An already-authenticated session belonging to the same user lists its
 *       pending approve-login requests and sees the same {@code matchNumber}.</li>
 *   <li>The approver decides allow/deny and echoes the number they see; on
 *       {@code allow} with a matching number we mint a real access token plus a
 *       persisted rotating refresh token and stash them on the session.</li>
 *   <li>The original client polls the session and receives the tokens once the
 *       status flips to APPROVED.</li>
 * </ol>
 *
 * <p>Tokens are minted with the same {@link TokenGenerationPort} +
 * {@link RefreshTokenService} pair the usernameless passkey login uses, so the
 * refresh token is a real persisted rotating token (not the placeholder UUID
 * the older QR service stored).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ApproveLoginService {

    private final StringRedisTemplate redisTemplate;
    private final TokenGenerationPort tokenGenerator;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final UsernamelessLoginFlowService usernamelessLoginFlowService;

    static final Duration SESSION_TTL = Duration.ofMinutes(2);
    private static final Duration APPROVED_TTL = Duration.ofMinutes(2);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String SESSION_PREFIX = "approve_login:session:";
    private static final String USER_INDEX_PREFIX = "approve_login:user:";

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_APPROVED = "APPROVED";
    public static final String STATUS_DENIED = "DENIED";
    public static final String STATUS_EXPIRED = "EXPIRED";

    /** Marks a session as a mid-MFA-flow APPROVE_LOGIN FACTOR (not a fresh login). */
    private static final String STEP_BOUND = "stepBound";
    /** The user this step-bound session is issued for (only THEY may satisfy it). */
    private static final String BOUND_USER = "boundUserId";
    /** The user whose phone actually approved the session. */
    private static final String APPROVER_USER = "approverUserId";

    /**
     * Creates a pending approve-login session for the account identified by
     * {@code email}. To avoid acting as an account-existence oracle the
     * response shape is identical whether or not the email resolves to a user:
     * a session id + a fresh match number + PENDING are always returned. When
     * the email does not resolve we still create a decoy session that can never
     * be approved (no user is indexed for it), so it simply expires.
     */
    public Map<String, Object> createSession(String email, String initiatorIp, String initiatorUserAgent) {
        String sessionId = UUID.randomUUID().toString();
        String matchNumber = String.format(Locale.ROOT, "%02d", RANDOM.nextInt(100));
        long now = Instant.now().getEpochSecond();
        long expiresAt = now + SESSION_TTL.getSeconds();

        Optional<User> user = email == null ? Optional.empty()
                : userRepository.findByEmail(email.trim().toLowerCase(Locale.ROOT));

        Map<String, String> sessionData = new HashMap<>();
        sessionData.put("status", STATUS_PENDING);
        sessionData.put("matchNumber", matchNumber);
        sessionData.put("email", email != null ? email : "");
        sessionData.put("initiatorIp", initiatorIp != null ? initiatorIp : "");
        sessionData.put("initiatorUserAgent", initiatorUserAgent != null ? initiatorUserAgent : "");
        sessionData.put("createdAt", String.valueOf(now));
        sessionData.put("expiresAt", String.valueOf(expiresAt));
        user.ifPresent(u -> sessionData.put("userId", u.getId().toString()));

        String key = SESSION_PREFIX + sessionId;
        redisTemplate.opsForHash().putAll(key, sessionData);
        redisTemplate.expire(key, SESSION_TTL);

        // Index by approver so the authenticated owner can list their pending
        // requests. Only real users get indexed; decoy sessions never surface.
        user.ifPresent(u -> {
            String indexKey = USER_INDEX_PREFIX + u.getId();
            redisTemplate.opsForSet().add(indexKey, sessionId);
            redisTemplate.expire(indexKey, SESSION_TTL);
        });

        log.info("Approve-login session created: {} (resolved={})", sessionId, user.isPresent());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);
        response.put("matchNumber", matchNumber);
        response.put("status", STATUS_PENDING);
        response.put("expiresAtEpochSeconds", expiresAt);
        return response;
    }

    /**
     * Polling endpoint for the original (unauthenticated) client. Returns the
     * current status and, once APPROVED, the minted tokens.
     */
    public Map<String, Object> getSession(String sessionId) {
        String key = SESSION_PREFIX + sessionId;
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);

        if (data.isEmpty()) {
            response.put("status", STATUS_EXPIRED);
            return response;
        }

        String status = (String) data.get("status");
        response.put("status", status);

        if (STATUS_APPROVED.equals(status)) {
            // When the tenant flow needs more steps the approver stashed an
            // mfaSessionToken instead of tokens — surface MFA_PENDING so the
            // polling client steps up via /api/v1/auth/mfa/step (task #16 B).
            if ("true".equals(data.get("mfaRequired"))) {
                response.put("mfaRequired", true);
                response.put("mfaSessionToken", data.get("mfaSessionToken"));
                String currentStep = (String) data.get("currentStep");
                String totalSteps = (String) data.get("totalSteps");
                response.put("currentStep", currentStep != null ? Integer.parseInt(currentStep) : 2);
                response.put("totalSteps", totalSteps != null ? Integer.parseInt(totalSteps) : 0);
                // The NEXT step's selectable methods (issue #2/#6). Always an array
                // (empty when nothing was stored — backward compatible for old
                // sessions written before this field existed).
                response.put("availableMethods", parseAvailableMethods((String) data.get("availableMethods")));
                response.put("role", data.get("role"));
            } else {
                response.put("accessToken", data.get("accessToken"));
                response.put("refreshToken", data.get("refreshToken"));
                String expiresIn = (String) data.get("expiresIn");
                response.put("expiresIn", expiresIn != null ? Long.parseLong(expiresIn) : 0L);
                response.put("role", data.get("role"));
            }
        }

        return response;
    }

    /**
     * Parses the stored CSV of AuthMethodType NAME strings back into a list for
     * the poll response. A null/blank value (old session, or a step with no
     * resolvable methods) yields an empty list — never null — so the wire shape
     * is a stable JSON array.
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

    /**
     * Lists the pending approve-login requests for the authenticated approver.
     * Drains any stale (expired) session ids from the index along the way.
     */
    public List<Map<String, Object>> listPending(UUID approverId) {
        String indexKey = USER_INDEX_PREFIX + approverId;
        Set<String> sessionIds = redisTemplate.opsForSet().members(indexKey);
        List<Map<String, Object>> pending = new ArrayList<>();
        if (sessionIds == null || sessionIds.isEmpty()) {
            return pending;
        }

        for (String sessionId : sessionIds) {
            String key = SESSION_PREFIX + sessionId;
            Map<Object, Object> data = redisTemplate.opsForHash().entries(key);
            if (data.isEmpty() || !STATUS_PENDING.equals(data.get("status"))) {
                // Expired or already decided — prune the index entry.
                redisTemplate.opsForSet().remove(indexKey, sessionId);
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("sessionId", sessionId);
            entry.put("matchNumber", data.get("matchNumber"));
            entry.put("initiatorIp", data.get("initiatorIp"));
            entry.put("initiatorUserAgent", data.get("initiatorUserAgent"));
            String createdAt = (String) data.get("createdAt");
            entry.put("createdAtEpochSeconds", createdAt != null ? Long.parseLong(createdAt) : 0L);
            pending.add(entry);
        }
        return pending;
    }

    /**
     * Decision endpoint for the authenticated approver. {@code decision} is
     * "allow" or "deny"; on "allow" the {@code matchNumber} the approver
     * presents must equal the session's number and the session must belong to
     * the approver. On a successful allow we mint tokens for the initiator to
     * poll.
     *
     * @param ip        approver request IP (recorded on the minted refresh token)
     * @param userAgent approver request UA (recorded on the minted refresh token)
     */
    public Map<String, Object> decide(String sessionId, UUID approverId, String decision,
                                       String presentedNumber, String ip, String userAgent) {
        String key = SESSION_PREFIX + sessionId;
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);

        if (data.isEmpty()) {
            response.put("status", STATUS_EXPIRED);
            response.put("message", "Session not found or expired");
            return response;
        }

        String status = (String) data.get("status");
        if (!STATUS_PENDING.equals(status)) {
            response.put("status", status);
            response.put("message", "Session already " + status.toLowerCase(Locale.ROOT));
            return response;
        }

        // The session must belong to the approver. Decoy sessions (no userId)
        // can never be approved.
        String ownerId = (String) data.get("userId");
        if (ownerId == null || !ownerId.equals(approverId.toString())) {
            log.warn("Approve-login decide: session {} does not belong to approver {}", sessionId, approverId);
            response.put("status", STATUS_PENDING);
            response.put("message", "Not authorized to decide this session");
            return response;
        }

        boolean allow = "allow".equalsIgnoreCase(decision);
        if (!allow) {
            redisTemplate.opsForHash().put(key, "status", STATUS_DENIED);
            redisTemplate.expire(key, APPROVED_TTL);
            redisTemplate.opsForSet().remove(USER_INDEX_PREFIX + approverId, sessionId);
            log.info("Approve-login session denied: {} by {}", sessionId, approverId);
            response.put("status", STATUS_DENIED);
            response.put("message", "Login denied");
            return response;
        }

        // Number-matching: the approver must echo the number their device shows.
        // matchNumber is a zero-padded two-digit STRING (e.g. "07"). Compare as
        // a zero-pad-normalized string so a client that accidentally drops the
        // leading zero (parsed "07" → 7 → "7") still matches — without ever
        // coercing it through a numeric type on either side (which is what loses
        // the leading zero in the first place). Defensive, demo-day hardening.
        String expectedNumber = (String) data.get("matchNumber");
        if (!matchNumbersEqual(expectedNumber, presentedNumber)) {
            log.warn("Approve-login decide: match-number mismatch for session {}", sessionId);
            response.put("status", STATUS_PENDING);
            response.put("message", "Match number does not match");
            return response;
        }

        // Step-bound (mid-MFA-flow APPROVE_LOGIN FACTOR): no token mint / no login
        // outcome — just record the approver + mark APPROVED. The factor handler
        // (ApproveLoginVerifyMfaStepHandler) verifies approverUserId == the user
        // being authenticated. The owner check above already proved approverId owns
        // the session, and the bound user IS the owner, so this is genuine proof.
        if ("true".equals(data.get(STEP_BOUND))) {
            Map<String, String> stepUpdates = new HashMap<>();
            stepUpdates.put("status", STATUS_APPROVED);
            stepUpdates.put(APPROVER_USER, approverId.toString());
            redisTemplate.opsForHash().putAll(key, stepUpdates);
            redisTemplate.expire(key, APPROVED_TTL);
            redisTemplate.opsForSet().remove(USER_INDEX_PREFIX + approverId, sessionId);
            log.info("Approve-login STEP session approved: {} by {}", sessionId, approverId);
            response.put("status", STATUS_APPROVED);
            response.put("message", "Approved");
            return response;
        }

        Optional<User> approver = userRepository.findByEmail(
                ((String) data.get("email")).trim().toLowerCase(Locale.ROOT));
        if (approver.isEmpty() || !approver.get().getId().toString().equals(ownerId)) {
            response.put("status", STATUS_PENDING);
            response.put("message", "Approver not found");
            return response;
        }

        User user = approver.get();
        String role = user.getRoleNames().stream()
                .findFirst()
                .orElseGet(() -> user.getUserType() != null ? user.getUserType().name() : "USER");

        // Bridge the proven approve-login factor (a usernameless Layer-1) INTO
        // the tenant's config-driven APP_LOGIN flow (task #16 B). If the tenant
        // configured Layer-2+ steps we stash an mfaSessionToken on the session
        // (NOT tokens); the initiator polls, sees MFA_PENDING, and completes the
        // remaining steps via /api/v1/auth/mfa/step. Only a 1-step / no-flow
        // tenant mints tokens here.
        UsernamelessLoginFlowService.FlowOutcome outcome =
                usernamelessLoginFlowService.continueAfterLayer1(
                        user, AuthMethodType.APPROVE_LOGIN, "approve_login", ip, userAgent, null);

        Map<String, String> updates = new HashMap<>();
        if (outcome.mfaPending()) {
            updates.put("status", STATUS_APPROVED);
            updates.put("mfaRequired", "true");
            updates.put("mfaSessionToken", outcome.mfaSessionToken());
            updates.put("currentStep", String.valueOf(outcome.currentStep()));
            updates.put("totalSteps", String.valueOf(outcome.totalSteps()));
            // Carry the NEXT step's selectable methods so the polling web client can
            // render the method picker (issue #2/#6). Stored CSV of AuthMethodType
            // NAME strings (uppercase enum names — no embedded commas). Backward-
            // compatible: an absent/empty key surfaces as an empty array in getSession.
            updates.put("availableMethods", String.join(",", outcome.availableMethods()));
            updates.put("role", role);
        } else {
            updates.put("status", STATUS_APPROVED);
            updates.put("accessToken", outcome.accessToken());
            updates.put("refreshToken", outcome.refreshToken());
            updates.put("role", role);
            updates.put("expiresIn", String.valueOf(outcome.expiresIn() / 1000));
        }
        redisTemplate.opsForHash().putAll(key, updates);
        redisTemplate.expire(key, APPROVED_TTL);
        redisTemplate.opsForSet().remove(USER_INDEX_PREFIX + approverId, sessionId);

        log.info("Approve-login session approved: {} by {} (mfaPending={})",
                sessionId, approverId, outcome.mfaPending());

        response.put("status", STATUS_APPROVED);
        response.put("message", outcome.mfaPending() ? "Login approved — additional verification required"
                : "Login approved");
        return response;
    }

    /**
     * Create a STEP-BOUND approve-login session for a mid-MFA-flow APPROVE_LOGIN
     * FACTOR. Bound to the user currently being authenticated (no email lookup —
     * the handler already has the user). Indexed under the user so it surfaces in
     * THEIR mobile "Login Requests" / {@code listPending}; the approver decides
     * via the SAME {@code /auth/approve-login/{id}/decide} endpoint (no mobile
     * change). {@link #decide} mints NO tokens for it; {@link #isStepApprovedBy}
     * is the cross-device proof that completes the step.
     */
    public Map<String, Object> createStepSession(UUID userId) {
        String sessionId = UUID.randomUUID().toString();
        String matchNumber = String.format(Locale.ROOT, "%02d", RANDOM.nextInt(100));
        long now = Instant.now().getEpochSecond();
        long expiresAt = now + SESSION_TTL.getSeconds();

        Map<String, String> sessionData = new HashMap<>();
        sessionData.put("status", STATUS_PENDING);
        sessionData.put("matchNumber", matchNumber);
        sessionData.put("userId", userId.toString());
        sessionData.put(STEP_BOUND, "true");
        sessionData.put(BOUND_USER, userId.toString());
        sessionData.put("createdAt", String.valueOf(now));
        sessionData.put("expiresAt", String.valueOf(expiresAt));

        String key = SESSION_PREFIX + sessionId;
        redisTemplate.opsForHash().putAll(key, sessionData);
        redisTemplate.expire(key, SESSION_TTL);

        String indexKey = USER_INDEX_PREFIX + userId;
        redisTemplate.opsForSet().add(indexKey, sessionId);
        redisTemplate.expire(indexKey, SESSION_TTL);

        log.info("Approve-login STEP session created: {} for user {}", sessionId, userId);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sessionId", sessionId);
        response.put("matchNumber", matchNumber);
        response.put("status", STATUS_PENDING);
        response.put("expiresAtEpochSeconds", expiresAt);
        return response;
    }

    /**
     * True iff a STEP-BOUND session was APPROVED by exactly the bound user — the
     * phone that approved it belongs to the same person being authenticated.
     * Single-use: consumes the session on a successful match.
     */
    public boolean isStepApprovedBy(String sessionId, UUID userId) {
        if (sessionId == null || sessionId.isBlank() || userId == null) {
            return false;
        }
        String key = SESSION_PREFIX + sessionId;
        Map<Object, Object> data = redisTemplate.opsForHash().entries(key);
        if (data.isEmpty()) {
            return false;
        }
        String want = userId.toString();
        boolean match = "true".equals(data.get(STEP_BOUND))
                && STATUS_APPROVED.equals(data.get("status"))
                && want.equals(data.get(APPROVER_USER))
                && want.equals(data.get(BOUND_USER));
        if (match) {
            redisTemplate.delete(key); // single-use
        }
        return match;
    }

    /**
     * Zero-pad-safe match-number comparison. Trims, and if BOTH sides are purely
     * numeric, left-pads each to two digits before comparing — so "07" and "7"
     * (a client that dropped the leading zero) still match. Non-numeric or null
     * inputs never match. Never routes the value through an int (that is exactly
     * what strips the leading zero).
     */
    static boolean matchNumbersEqual(String expected, String presented) {
        if (expected == null || presented == null) {
            return false;
        }
        String e = expected.trim();
        String p = presented.trim();
        if (e.isEmpty() || p.isEmpty()) {
            return false;
        }
        if (e.equals(p)) {
            return true;
        }
        // Only normalize when both are short numeric strings (the match-number
        // domain) — avoids surprising matches for arbitrary strings.
        if (e.matches("\\d{1,2}") && p.matches("\\d{1,2}")) {
            return padTwo(e).equals(padTwo(p));
        }
        return false;
    }

    private static String padTwo(String n) {
        return n.length() == 1 ? "0" + n : n;
    }
}
