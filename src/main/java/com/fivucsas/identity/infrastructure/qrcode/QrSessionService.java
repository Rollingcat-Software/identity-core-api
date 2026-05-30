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

        User user = approver.get();
        String role = user.getRoleNames().stream()
                .findFirst()
                .orElseGet(() -> user.getUserType() != null ? user.getUserType().name() : "USER");

        // Bridge the proven QR scan-to-approve (a usernameless Layer-1 factor)
        // INTO the tenant's config-driven APP_LOGIN flow (task #16 B). When the
        // tenant configured Layer-2+ steps we stash an mfaSessionToken (NOT
        // tokens) and the polling client steps up via /api/v1/auth/mfa/step.
        // Only a 1-step / no-flow tenant mints tokens here. This also replaces
        // the old placeholder-UUID refresh token with a real persisted rotating
        // token for the single-factor path.
        UsernamelessLoginFlowService.FlowOutcome outcome =
                usernamelessLoginFlowService.continueAfterLayer1(
                        user, AuthMethodType.QR_CODE, "mca", null, null, null);

        Map<String, String> updates = new HashMap<>();
        updates.put("status", "APPROVED");
        updates.put("role", role);
        if (outcome.mfaPending()) {
            updates.put("mfaRequired", "true");
            updates.put("mfaSessionToken", outcome.mfaSessionToken());
            updates.put("currentStep", String.valueOf(outcome.currentStep()));
            updates.put("totalSteps", String.valueOf(outcome.totalSteps()));
        } else {
            updates.put("accessToken", outcome.accessToken());
            updates.put("refreshToken", outcome.refreshToken());
            updates.put("expiresIn", String.valueOf(outcome.expiresIn() / 1000));
        }

        redisTemplate.opsForHash().putAll(key, updates);
        redisTemplate.expire(key, Duration.ofMinutes(2));

        log.info("QR session approved: {} by user: {} (mfaPending={})",
                sessionId, approverId, outcome.mfaPending());

        return Map.of(
                "sessionId", sessionId,
                "qrContent", data.get("qrContent"),
                "status", "APPROVED",
                "message", outcome.mfaPending() ? "Login approved — additional verification required"
                        : "Login approved"
        );
    }
}
