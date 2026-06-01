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
        sendOtp(to, code, OtpPurpose.LOGIN_VERIFICATION, null);
    }

    @Override
    public void sendOtp(String to, String code, OtpPurpose purpose, String locale) {
        log.info("Mail disabled - OTP for {} (purpose={}, locale={}): {}",
                to, purpose, locale, code);
    }

    @Override
    public void sendGuestInvitation(String to, String token, Instant accessStart, Instant accessEnd,
                                    String message, String inviterName, String tenantName, String locale) {
        log.info("Mail disabled - guest invitation for {} (token={}, access {} -> {}, invitedBy={}, "
                        + "tenant='{}', locale={})",
                to, token, accessStart, accessEnd, inviterName, tenantName, locale);
    }

    @Override
    public void sendTenantOnboardingVerification(String to, String adminName, String orgName, String token) {
        log.info("Mail disabled - tenant onboarding verification for {} (org='{}', token={})",
                to, orgName, token);
    }
}
