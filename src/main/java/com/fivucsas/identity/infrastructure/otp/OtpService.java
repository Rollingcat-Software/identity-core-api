package com.fivucsas.identity.infrastructure.otp;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpService {

    private final StringRedisTemplate redisTemplate;

    private static final int OTP_LENGTH = 6;
    private static final Duration OTP_TTL = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();

    public String generate(String key) {
        String code = generateCode();
        redisTemplate.opsForValue().set(key, code, OTP_TTL);
        log.debug("OTP generated for key: {}", key);
        return code;
    }

    public boolean validate(String key, String code) {
        String stored = redisTemplate.opsForValue().get(key);
        if (stored == null) {
            log.debug("OTP not found or expired for key: {}", key);
            return false;
        }
        boolean valid = stored.equals(code);
        if (valid) {
            redisTemplate.delete(key);
            log.debug("OTP validated and consumed for key: {}", key);
        } else {
            log.debug("OTP validation failed for key: {}", key);
        }
        return valid;
    }

    public void invalidate(String key) {
        redisTemplate.delete(key);
    }

    private String generateCode() {
        int bound = (int) Math.pow(10, OTP_LENGTH);
        int code = RANDOM.nextInt(bound);
        return String.format("%0" + OTP_LENGTH + "d", code);
    }
}
