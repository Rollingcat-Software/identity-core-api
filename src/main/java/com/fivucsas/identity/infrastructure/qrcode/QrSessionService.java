package com.fivucsas.identity.infrastructure.qrcode;

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
            String accessToken = (String) data.get("accessToken");
            String refreshToken = (String) data.get("refreshToken");
            String role = (String) data.get("role");
            String expiresIn = (String) data.get("expiresIn");

            response.put("accessToken", accessToken);
            response.put("refreshToken", refreshToken);
            response.put("role", role);
            response.put("expiresIn", expiresIn != null ? Long.parseLong(expiresIn) : 0);
            response.put("message", "Login approved");
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
        String accessToken = jwtService.generateAccessToken(user.getEmail());
        long expiresIn = jwtService.getExpirationMillis() / 1000;
        String role = user.getRoleNames().stream()
                .findFirst()
                .orElseGet(() -> user.getUserType() != null ? user.getUserType().name() : "USER");

        Map<String, String> updates = new HashMap<>();
        updates.put("status", "APPROVED");
        updates.put("accessToken", accessToken);
        updates.put("refreshToken", UUID.randomUUID().toString());
        updates.put("role", role);
        updates.put("expiresIn", String.valueOf(expiresIn));

        redisTemplate.opsForHash().putAll(key, updates);
        redisTemplate.expire(key, Duration.ofMinutes(2));

        log.info("QR session approved: {} by user: {}", sessionId, approverId);

        return Map.of(
                "sessionId", sessionId,
                "qrContent", data.get("qrContent"),
                "status", "APPROVED",
                "message", "Login approved"
        );
    }
}
