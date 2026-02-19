package com.fivucsas.identity.infrastructure.sms;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "sms.enabled", havingValue = "false", matchIfMissing = true)
@Slf4j
public class NoOpSmsService implements SmsService {

    @Override
    public void sendOtp(String phoneNumber, String code) {
        log.info("SMS disabled - OTP for {}: {}", phoneNumber, code);
    }
}
