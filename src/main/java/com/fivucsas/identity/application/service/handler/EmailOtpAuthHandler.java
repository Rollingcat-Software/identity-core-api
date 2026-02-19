package com.fivucsas.identity.application.service.handler;

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

        // If action is "send", generate and send OTP
        if ("send".equals(action)) {
            return sendOtp(session, step);
        }

        // Otherwise validate the submitted code
        String code = (String) data.get("code");

        if (code == null || code.isEmpty()) {
            return StepResult.failure("OTP code is required");
        }

        String otpKey = buildOtpKey(session.getId().toString(), step.getStepOrder());
        boolean valid = otpService.validate(otpKey, code);

        if (!valid) {
            log.warn("Email OTP validation failed for session: {}", session.getId());
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
