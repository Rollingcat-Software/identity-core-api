package com.fivucsas.identity.application.service.mfa.handler;

import com.fivucsas.identity.application.service.mfa.MfaStepResult;
import com.fivucsas.identity.application.service.mfa.VerifyMfaStepHandler;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.totp.TotpService;
import com.fivucsas.identity.security.TotpSecretCipher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class TotpVerifyMfaStepHandler implements VerifyMfaStepHandler {

    private final TotpService totpService;
    private final StringRedisTemplate redisTemplate;
    private final TotpSecretCipher totpSecretCipher;

    @Override
    public AuthMethodType supports() {
        return AuthMethodType.TOTP;
    }

    @Override
    public MfaStepResult verify(MfaSession session, User user, Map<String, Object> data) {
        String code = (String) data.get("code");
        if (code == null || code.isBlank()) {
            return MfaStepResult.fail();
        }
        String secret = resolveTotpSecret(user);
        boolean ok = secret != null && totpService.verifyCode(secret, code);
        return ok ? MfaStepResult.ok() : MfaStepResult.fail();
    }

    /**
     * Resolve TOTP secret: try Redis (cache) first, fall back to PostgreSQL
     * (source of truth). DB value may be {@code enc:v1:...} (encrypted) or
     * legacy plaintext — {@link TotpSecretCipher#decryptIfNeeded(String)}
     * handles both. Re-cache plaintext in Redis for fast subsequent lookups.
     */
    private String resolveTotpSecret(User user) {
        String redisKey = "totp:secret:" + user.getId();
        String secret = redisTemplate.opsForValue().get(redisKey);
        if (secret == null && user.getTwoFactorSecret() != null) {
            secret = totpSecretCipher.decryptIfNeeded(user.getTwoFactorSecret());
            redisTemplate.opsForValue().set(redisKey, secret);
            log.info("TOTP secret re-cached in Redis for user: {}", user.getId());
        }
        return secret;
    }
}
