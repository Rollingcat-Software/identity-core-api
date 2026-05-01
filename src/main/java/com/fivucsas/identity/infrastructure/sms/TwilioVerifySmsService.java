package com.fivucsas.identity.infrastructure.sms;

import com.twilio.Twilio;
import com.twilio.rest.verify.v2.service.Verification;
import com.twilio.rest.verify.v2.service.VerificationCheck;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "sms.provider", havingValue = "twilio-verify")
@Slf4j
public class TwilioVerifySmsService implements SmsService, VerifiableSmsService {

    @Value("${sms.twilio.account-sid}")
    private String accountSid;

    @Value("${sms.twilio.auth-token}")
    private String authToken;

    @Value("${sms.twilio.verify-service-sid}")
    private String verifyServiceSid;

    @PostConstruct
    void init() {
        Twilio.init(accountSid, authToken);
        log.info("Twilio Verify SMS service initialized, service SID: {}", verifyServiceSid);
    }

    /**
     * Sends an OTP via Twilio Verify. The {@code code} param is ignored —
     * Twilio generates and manages the code internally.
     */
    @Override
    public void sendOtp(String phoneNumber, String code) {
        try {
            Verification verification = Verification.creator(verifyServiceSid, phoneNumber, "sms")
                    .setLocale("tr")
                    .create();
            log.info("Twilio Verify OTP sent to {} — status: {}", phoneNumber, verification.getStatus());
        } catch (Exception e) {
            log.error("Failed to send Twilio Verify OTP to {}: {}", phoneNumber, e.getMessage());
            throw new RuntimeException("SMS delivery failed", e);
        }
    }

    /**
     * Verifies the code the user entered against Twilio Verify and returns
     * a typed result distinguishing "wrong code" (provider returned a non-
     * approved status) from "provider error" (network / SDK exception).
     */
    @Override
    public VerifyResult verifyCodeDetailed(String phoneNumber, String code) {
        VerificationCheck check;
        try {
            check = VerificationCheck.creator(verifyServiceSid)
                    .setTo(phoneNumber)
                    .setCode(code)
                    .create();
        } catch (Exception e) {
            // Pass the exception as the last arg so SLF4J logs the full
            // stack trace (not just e.getMessage(), which loses the cause
            // chain — e.g. wrapped TimeoutException inside ApiException).
            log.warn("Twilio Verify check failed for {}: {}", phoneNumber, e.getMessage(), e);
            return VerifyResult.PROVIDER_ERROR;
        }
        log.info("Twilio Verify check for {} — status: {}", phoneNumber, check.getStatus());
        return "approved".equals(check.getStatus())
                ? VerifyResult.APPROVED
                : VerifyResult.INVALID_CODE;
    }
}
