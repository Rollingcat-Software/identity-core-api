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
 * Handles FACE_MATCH verification step.
 * Compares a live face image against the document photo via biometric-processor.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class FaceMatchHandler implements VerificationStepHandler {

    private final BiometricProcessorClient processorClient;

    @Value("${verification.face-match.threshold:0.7}")
    private double matchThreshold;

    @Override
    public String getStepType() {
        return "FACE_MATCH";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String liveFace = (String) data.get("live_face");
        String documentFace = (String) data.get("document_face");

        if (liveFace == null || liveFace.isBlank()) {
            return VerificationStepResult.failure("Live face image is required");
        }
        if (documentFace == null || documentFace.isBlank()) {
            return VerificationStepResult.failure("Document face image is required");
        }

        try {
            Map<String, Object> response = processorClient.faceMatch(liveFace, documentFace);

            // Check for client-side error responses from BiometricProcessorClient
            if (Boolean.FALSE.equals(response.get("success"))) {
                String error = (String) response.getOrDefault("error", "Face match failed");
                return VerificationStepResult.failure(error);
            }

            // Biometric-processor returns: match, confidence, similarity, distance, threshold
            // Use "similarity" as the match score (0..1, higher = more similar)
            Double matchScore = parseDouble(response.get("similarity"));
            if (matchScore == null) {
                matchScore = parseDouble(response.get("confidence"));
            }
            boolean matched = Boolean.TRUE.equals(response.get("match"));

            // Fallback: also check score against our threshold
            if (!matched && matchScore != null && matchScore >= matchThreshold) {
                matched = true;
            }

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("match_score", matchScore);
            resultData.put("threshold", matchThreshold);
            resultData.put("matched", matched);
            resultData.put("distance", parseDouble(response.get("distance")));

            if (matched) {
                log.info("Face match passed for session {}: score={}", session.getId(), matchScore);
                return VerificationStepResult.success(matchScore, resultData);
            } else {
                log.warn("Face match failed for session {}: score={}, threshold={}",
                        session.getId(), matchScore, matchThreshold);
                return VerificationStepResult.failure("Face match score below threshold", resultData);
            }
        } catch (Exception e) {
            log.error("Face match error for session {}: {}", session.getId(), e.getMessage(), e);
            return VerificationStepResult.failure("Face match service unavailable");
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
