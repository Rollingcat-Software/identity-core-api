package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.application.port.output.MarkPhoneVerifiedPort;
import com.fivucsas.identity.domain.exception.OtpAttemptsExhaustedException;
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
    // F2 (2026-06-06): a verified SMS_OTP login step proves phone ownership, so
    // mark phone_number_verified (keyed by userId → adapter owns the entity.User
    // write). Phone stays OPTIONAL — only corrects the claim on SMS_OTP login.
    private final MarkPhoneVerifiedPort markPhoneVerifiedPort;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.SMS_OTP;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String action = (String) data.get("action");

        if ("send".equals(action) || "send_otp".equals(action)) {
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
            // F2: verified SMS_OTP → phone is proven, set phone_number_verified.
            markPhoneVerifiedForSessionUser(session);
            return StepResult.success();
        }

        // Fallback: local Redis-based OTP validation
        String otpKey = buildOtpKey(session.getId().toString(), step.getStepOrder());
        // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §OTP-exhausted — surface
        // NIST 800-63B 5-strike exhaustion instead of the boolean overload.
        OtpService.ValidationResult result = otpService.validateWithResult(otpKey, code);
        if (result.isExhausted()) {
            log.warn("SMS OTP attempts exhausted for session: {} (user must request a new code)",
                    session.getId());
            throw new OtpAttemptsExhaustedException();
        }
        if (!result.isValid()) {
            log.warn("SMS OTP validation failed for session: {} (remaining={})",
                    session.getId(), result.getRemainingAttempts());
            return StepResult.failure("Invalid or expired SMS OTP code");
        }

        log.info("SMS OTP validation successful for session: {}", session.getId());
        // F2: verified SMS_OTP → phone is proven, set phone_number_verified.
        markPhoneVerifiedForSessionUser(session);
        return StepResult.success();
    }

    /**
     * F2: flip phone_number_verified for the session's user after a verified
     * SMS_OTP step. Null-safe (a missing user is a no-op) so it can never NPE a
     * successful login; the adapter additionally no-ops on a null/unknown id.
     */
    private void markPhoneVerifiedForSessionUser(AuthSession session) {
        if (session.getUser() != null) {
            markPhoneVerifiedPort.markPhoneVerified(session.getUser().getId());
        }
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
