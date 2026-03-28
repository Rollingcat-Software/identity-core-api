package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Handles PHONE_VERIFICATION step.
 * Reuses existing SMS OTP infrastructure for two-phase verification:
 *   action=send  -> sends OTP to provided phone number
 *   action=verify (default) -> validates submitted OTP code
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PhoneVerificationHandler implements VerificationStepHandler {

    private final OtpService otpService;
    private final SmsService smsService;

    @Override
    public String getStepType() {
        return "PHONE_VERIFICATION";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String action = (String) data.get("action");

        if ("send".equals(action)) {
            return sendOtp(session, stepNumber, data);
        }
        return verifyOtp(session, stepNumber, data);
    }

    private VerificationStepResult sendOtp(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String phoneNumber = (String) data.get("phone_number");
        if (phoneNumber == null || phoneNumber.isBlank()) {
            return VerificationStepResult.failure("Phone number is required");
        }

        String otpKey = buildOtpKey(session.getId().toString(), stepNumber);
        String code = otpService.generate(otpKey);
        smsService.sendOtp(phoneNumber, code);

        log.info("Phone verification OTP sent for session {}: phone={}", session.getId(), maskPhone(phoneNumber));
        return VerificationStepResult.success(Map.of(
                "otp_sent", true,
                "phone_number", maskPhone(phoneNumber)
        ));
    }

    private VerificationStepResult verifyOtp(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String code = (String) data.get("code");
        String phoneNumber = (String) data.get("phone_number");

        if (code == null || code.isBlank()) {
            return VerificationStepResult.failure("OTP code is required");
        }

        String otpKey = buildOtpKey(session.getId().toString(), stepNumber);
        boolean valid = otpService.validate(otpKey, code);

        if (!valid) {
            log.warn("Phone verification OTP invalid for session {}", session.getId());
            return VerificationStepResult.failure("Invalid or expired OTP code");
        }

        log.info("Phone verification OTP validated for session {}", session.getId());
        return VerificationStepResult.success(1.0, Map.of(
                "phone_number", phoneNumber != null ? phoneNumber : "",
                "verified", true
        ));
    }

    private String buildOtpKey(String sessionId, int stepNumber) {
        return "verification:" + sessionId + ":" + stepNumber + ":PHONE";
    }

    private String maskPhone(String phone) {
        if (phone == null || phone.length() < 6) return "***";
        return phone.substring(0, 4) + "***" + phone.substring(phone.length() - 2);
    }
}
