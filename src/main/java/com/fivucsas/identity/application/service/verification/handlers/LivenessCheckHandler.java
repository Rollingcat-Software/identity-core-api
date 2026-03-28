package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.infrastructure.adapter.BiometricProcessorClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Handles LIVENESS_CHECK verification step.
 * Delegates to biometric-processor for passive liveness detection.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LivenessCheckHandler implements VerificationStepHandler {

    private final BiometricProcessorClient processorClient;

    @Value("${verification.liveness.threshold:0.5}")
    private double livenessThreshold;

    @Override
    public String getStepType() {
        return "LIVENESS_CHECK";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String image = (String) data.get("image");
        if (image == null || image.isBlank()) {
            return VerificationStepResult.failure("Face image is required for liveness check");
        }

        try {
            Map<String, Object> response = processorClient.livenessCheck(image);

            if (Boolean.FALSE.equals(response.get("success"))) {
                String error = (String) response.getOrDefault("error", "Liveness check failed");
                return VerificationStepResult.failure(error);
            }

            // Biometric-processor returns: is_live, confidence, method
            Double livenessScore = parseDouble(response.get("confidence"));
            if (livenessScore == null) {
                livenessScore = parseDouble(response.get("liveness_score"));
            }
            boolean isLive = Boolean.TRUE.equals(response.get("is_live"));

            // Fall back to threshold comparison if no explicit is_live flag
            if (!isLive && livenessScore != null) {
                isLive = livenessScore >= livenessThreshold;
            }

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("liveness_score", livenessScore);
            resultData.put("is_live", isLive);
            resultData.put("threshold", livenessThreshold);

            if (isLive) {
                log.info("Liveness check passed for session {}: score={}", session.getId(), livenessScore);
                return VerificationStepResult.success(livenessScore, resultData);
            } else {
                log.warn("Liveness check failed for session {}: score={}", session.getId(), livenessScore);
                return VerificationStepResult.failure("Liveness check failed — possible spoof detected", resultData);
            }
        } catch (Exception e) {
            log.error("Liveness check error for session {}: {}", session.getId(), e.getMessage(), e);
            return VerificationStepResult.failure("Liveness check service unavailable");
        }
    }

    private Double parseDouble(Object value) {
        if (value instanceof Number num) return num.doubleValue();
        if (value instanceof String s) {
            try { return Double.parseDouble(s); } catch (NumberFormatException ignored) {}
        }
        return null;
    }
}
