package com.fivucsas.identity.application.service.handler;

import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.AuthFlowStep;
import com.fivucsas.identity.entity.AuthSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class VoiceAuthHandler implements AuthMethodHandler {

    private final BiometricServicePort biometricServicePort;

    @Override
    public AuthMethodType getMethodType() {
        return AuthMethodType.VOICE;
    }

    @Override
    public StepResult validate(AuthSession session, AuthFlowStep step, Map<String, Object> data) {
        String voiceData = (String) data.get("voiceData");

        if (voiceData == null || voiceData.isEmpty()) {
            return StepResult.failure("Voice recording data is required");
        }

        if (session.getUser() == null) {
            return StepResult.failure("User must be identified before voice verification");
        }

        try {
            Map<String, Object> result = biometricServicePort.verifyVoice(
                    session.getUser().getId(), voiceData);

            Object verified = result.get("verified");
            boolean isVerified = Boolean.TRUE.equals(verified)
                    || "true".equalsIgnoreCase(String.valueOf(verified));

            if (isVerified) {
                log.info("Voice verification successful for user: {}", session.getUser().getEmail());
                return StepResult.success(Map.of("verified", "true"));
            } else {
                log.warn("Voice verification failed for user: {}", session.getUser().getEmail());
                return StepResult.failure("Voice verification failed");
            }
        } catch (Exception e) {
            log.error("Voice verification error for session: {}", session.getId(), e);
            return StepResult.failure("Voice verification service unavailable");
        }
    }

    @Override
    public boolean requiresEnrollment() {
        return true;
    }

    @Override
    public Set<String> requiredDataFields() {
        return Set.of("voiceData");
    }
}
