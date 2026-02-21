package com.fivucsas.identity.infrastructure.totp;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TotpService {

    private static final int SECRET_LENGTH = 32;
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator(SECRET_LENGTH);
    private final CodeVerifier codeVerifier;

    public TotpService() {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    }

    public String generateSecret() {
        String secret = secretGenerator.generate();
        log.debug("TOTP secret generated");
        return secret;
    }

    public String buildOtpAuthUri(String secret, String email, String issuer) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                issuer, email, secret, issuer);
    }

    public boolean verifyCode(String secret, String code) {
        try {
            boolean valid = codeVerifier.isValidCode(secret, code);
            log.debug("TOTP code verification result: {}", valid);
            return valid;
        } catch (Exception e) {
            log.error("TOTP verification error", e);
            return false;
        }
    }
}
