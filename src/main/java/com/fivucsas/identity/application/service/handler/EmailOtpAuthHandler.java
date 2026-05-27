package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.domain.exception.OtpAttemptsExhaustedException;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class EmailOtpAuthHandler implements AuthMethodHandler {

    private final OtpService otpService;
    private final EmailService emailService;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.EMAIL_OTP;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String action = (String) data.get("action");

        // If action is "send" or "send_otp", generate and send OTP
        if ("send".equals(action) || "send_otp".equals(action)) {
            return sendOtp(session, step);
        }

        // Otherwise validate the submitted code
        String code = (String) data.get("code");

        if (code == null || code.isEmpty()) {
            return StepResult.failure("OTP code is required");
        }

        String otpKey = buildOtpKey(session.getId().toString(), step.getStepOrder());
        // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §OTP-exhausted — use
        // validateWithResult so we surface the NIST 800-63B 5-strike
        // exhaustion state. The boolean validate() overload throws the flag
        // away and forces users to wait the full 5-min TTL.
        OtpService.ValidationResult result = otpService.validateWithResult(otpKey, code);
        if (result.isExhausted()) {
            log.warn("Email OTP attempts exhausted for session: {} (user must request a new code)",
                    session.getId());
            throw new OtpAttemptsExhaustedException();
        }
        if (!result.isValid()) {
            log.warn("Email OTP validation failed for session: {} (remaining={})",
                    session.getId(), result.getRemainingAttempts());
            return StepResult.failure("Invalid or expired OTP code");
        }

        log.info("Email OTP validation successful for session: {}", session.getId());
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
            return StepResult.failure("User must be identified before sending OTP");
        }

        String otpKey = buildOtpKey(session.getId().toString(), step.getStepOrder());
        String code = otpService.generate(otpKey);
        emailService.sendOtp(session.getUser().getEmail(), code);

        log.info("OTP sent for session: {}", session.getId());
        return StepResult.success(Map.of("otpSent", "true"));
    }

    private String buildOtpKey(String sessionId, int stepOrder) {
        return "otp:" + sessionId + ":" + stepOrder + ":EMAIL_OTP";
    }
}
