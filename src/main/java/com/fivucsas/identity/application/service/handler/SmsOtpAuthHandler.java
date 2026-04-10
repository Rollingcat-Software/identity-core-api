package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.infrastructure.sms.SmsService;
import com.fivucsas.identity.infrastructure.sms.VerifiableSmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class SmsOtpAuthHandler implements AuthMethodHandler {

    private final OtpService otpService;
    private final SmsService smsService;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.SMS_OTP;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String action = (String) data.get("action");

        if ("send".equals(action)) {
            return sendOtp(session, step);
        }

        String code = (String) data.get("code");
        if (code == null || code.isEmpty()) {
            return StepResult.failure("SMS OTP code is required");
        }

        // Use Twilio Verify native check when available (no Redis OTP store needed)
        if (smsService instanceof VerifiableSmsService verifiable) {
            String phoneNumber = session.getUser() != null ? session.getUser().getPhoneNumber() : null;
            if (phoneNumber == null || phoneNumber.isEmpty()) {
                return StepResult.failure("User does not have a phone number configured");
            }
            boolean valid = verifiable.verifyCode(phoneNumber, code);
            if (!valid) {
                log.warn("Twilio Verify check failed for session: {}", session.getId());
                return StepResult.failure("Invalid or expired SMS OTP code");
            }
            log.info("Twilio Verify check succeeded for session: {}", session.getId());
            return StepResult.success();
        }

        // Fallback: local Redis-based OTP validation
        String otpKey = buildOtpKey(session.getId().toString(), step.getStepOrder());
        boolean valid = otpService.validate(otpKey, code);

        if (!valid) {
            log.warn("SMS OTP validation failed for session: {}", session.getId());
            return StepResult.failure("Invalid or expired SMS OTP code");
        }

        log.info("SMS OTP validation successful for session: {}", session.getId());
        return StepResult.success();
    }

    @Override
    public boolean requiresEnrollment() {
        return false;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("code");
    }

    private StepResult sendOtp(AuthSession session, AuthFlowStep step) {
        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before sending SMS OTP");
        }

        String phoneNumber = session.getUser().getPhoneNumber();
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            return StepResult.failure("User does not have a phone number configured");
        }

        String otpKey = buildOtpKey(session.getId().toString(), step.getStepOrder());
        String code = otpService.generate(otpKey);
        smsService.sendOtp(phoneNumber, code);

        log.info("SMS OTP sent for session: {}", session.getId());
        return StepResult.success(Map.of("otpSent", "true"));
    }

    private String buildOtpKey(String sessionId, int stepOrder) {
        return "otp:" + sessionId + ":" + stepOrder + ":SMS_OTP";
    }
}
