package com.fivucsas.identity.infrastructure.qrcode;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class QrCodeService {

    private final StringRedisTemplate redisTemplate;

    private static final Duration TOKEN_TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String QR_PREFIX = "qr:token:";

    public String generateToken(UUID userId) {
        byte[] tokenBytes = new byte[32];
        RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        String key = QR_PREFIX + token;
        redisTemplate.opsForValue().set(key, userId.toString(), TOKEN_TTL);
        log.debug("QR token generated for user: {}", userId);
        return token;
    }

    public boolean validateToken(String token, UUID userId) {
        String key = QR_PREFIX + token;
        String storedUserId = redisTemplate.opsForValue().get(key);

        if (storedUserId == null) {
            log.debug("QR token not found or expired: {}", token);
            return false;
        }

        boolean valid = storedUserId.equals(userId.toString());
        if (valid) {
            redisTemplate.delete(key);
            log.debug("QR token validated and consumed for user: {}", userId);
        } else {
            log.debug("QR token user mismatch. Expected: {}, Got: {}", storedUserId, userId);
        }
        return valid;
    }

    public void invalidateToken(String token) {
        redisTemplate.delete(QR_PREFIX + token);
    }
}
