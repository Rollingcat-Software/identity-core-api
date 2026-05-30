package com.fivucsas.identity.infrastructure.approvelogin;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
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

    static final Duration SESSION_TTL = Duration.ofMinutes(2);
    private static final Duration APPROVED_TTL = Duration.ofMinutes(2);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String SESSION_PREFIX = "approve_login:session:";
    private static final String USER_INDEX_PREFIX = "approve_login:user:";

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_APPROVED = "APPROVED";
    public static final String STATUS_DENIED = "DENIED";
    public static final String STATUS_EXPIRED = "EXPIRED";

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
            response.put("accessToken", data.get("accessToken"));
            response.put("refreshToken", data.get("refreshToken"));
            String expiresIn = (String) data.get("expiresIn");
            response.put("expiresIn", expiresIn != null ? Long.parseLong(expiresIn) : 0L);
            response.put("role", data.get("role"));
        }

        return response;
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
        String expectedNumber = (String) data.get("matchNumber");
        if (expectedNumber == null || !expectedNumber.equals(presentedNumber)) {
            log.warn("Approve-login decide: match-number mismatch for session {}", sessionId);
            response.put("status", STATUS_PENDING);
            response.put("message", "Match number does not match");
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
        String accessToken = tokenGenerator.generateAccessToken(user.getEmail(), List.of("approve_login"));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, ip, userAgent);
        long expiresIn = tokenGenerator.getExpirationMillis() / 1000;

        Map<String, String> updates = new HashMap<>();
        updates.put("status", STATUS_APPROVED);
        updates.put("accessToken", accessToken);
        updates.put("refreshToken", refreshToken.getToken());
        updates.put("role", role);
        updates.put("expiresIn", String.valueOf(expiresIn));
        redisTemplate.opsForHash().putAll(key, updates);
        redisTemplate.expire(key, APPROVED_TTL);
        redisTemplate.opsForSet().remove(USER_INDEX_PREFIX + approverId, sessionId);

        log.info("Approve-login session approved: {} by {}", sessionId, approverId);

        response.put("status", STATUS_APPROVED);
        response.put("message", "Login approved");
        return response;
    }
}
