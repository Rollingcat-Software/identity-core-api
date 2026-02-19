package com.fivucsas.identity.infrastructure.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "mail.enabled", havingValue = "false", matchIfMissing = true)
@Slf4j
public class NoOpEmailService implements EmailService {

    @Override
    public void sendOtp(String to, String code) {
        log.info("Mail disabled - OTP for {}: {}", to, code);
    }
}
