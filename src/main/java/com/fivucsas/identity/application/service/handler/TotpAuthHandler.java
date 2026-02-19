package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class TotpAuthHandler implements AuthMethodHandler {

    private static final String ISSUER = "FIVUCSAS";

    private final TotpService totpService;
    private final StringRedisTemplate redisTemplate;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.TOTP;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String action = (String) data.get("action");

        if ("setup".equals(action)) {
            return setupTotp(session);
        }

        String code = (String) data.get("code");
        if (code == null || code.isEmpty()) {
            return StepResult.failure("TOTP code is required");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before TOTP verification");
        }

        String secretKey = buildSecretKey(session.getUser().getId().toString());
        String secret = redisTemplate.opsForValue().get(secretKey);

        if (secret == null) {
            return StepResult.failure("TOTP not configured for this user");
        }

        boolean valid = totpService.verifyCode(secret, code);
        if (!valid) {
            log.warn("TOTP validation failed for session: {}", session.getId());
            return StepResult.failure("Invalid TOTP code");
        }

        log.info("TOTP validation successful for session: {}", session.getId());
        return StepResult.success();
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("code");
    }

    private StepResult setupTotp(AuthSession session) {
        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before TOTP setup");
        }

        String secret = totpService.generateSecret();
        String secretKey = buildSecretKey(session.getUser().getId().toString());
        redisTemplate.opsForValue().set(secretKey, secret);

        String otpAuthUri = totpService.buildOtpAuthUri(
                secret, session.getUser().getEmail(), ISSUER);

        log.info("TOTP setup initiated for user: {}", session.getUser().getEmail());
        return StepResult.success(Map.of(
                "secret", secret,
                "otpAuthUri", otpAuthUri
        ));
    }

    private String buildSecretKey(String userId) {
        return "totp:secret:" + userId;
    }
}
