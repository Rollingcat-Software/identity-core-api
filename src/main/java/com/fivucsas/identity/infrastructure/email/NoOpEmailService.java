package com.fivucsas.identity.infrastructure.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@ConditionalOnProperty(name = "mail.enabled", havingValue = "false", matchIfMissing = true)
@Slf4j
public class NoOpEmailService implements EmailService {

    @Override
    public void sendOtp(String to, String code) {
        log.info("Mail disabled - OTP for {}: {}", to, code);
    }

    @Override
    public void sendGuestInvitation(String to, String token, Instant accessStart, Instant accessEnd,
                                    String message, String inviterName) {
        log.info("Mail disabled - guest invitation for {} (token={}, access {} -> {}, invitedBy={})",
                to, token, accessStart, accessEnd, inviterName);
    }

    @Override
    public void sendTenantOnboardingVerification(String to, String adminName, String orgName, String token) {
        log.info("Mail disabled - tenant onboarding verification for {} (org='{}', token={})",
                to, orgName, token);
    }
}
