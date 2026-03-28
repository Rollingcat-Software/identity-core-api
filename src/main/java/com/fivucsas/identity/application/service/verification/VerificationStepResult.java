package com.fivucsas.identity.application.service.verification;

import java.util.Map;

/**
 * Result returned by a VerificationStepHandler after executing a verification step.
 */
public record VerificationStepResult(
        boolean passed,
        Double confidence,
        Map<String, Object> resultData,
        String errorMessage
) {
    public static VerificationStepResult success(Double confidence, Map<String, Object> resultData) {
        return new VerificationStepResult(true, confidence, resultData, null);
    }

    public static VerificationStepResult success(Map<String, Object> resultData) {
        return new VerificationStepResult(true, null, resultData, null);
    }

    public static VerificationStepResult failure(String errorMessage) {
        return new VerificationStepResult(false, null, Map.of(), errorMessage);
    }

    public static VerificationStepResult failure(String errorMessage, Map<String, Object> resultData) {
        return new VerificationStepResult(false, null, resultData, errorMessage);
    }

    /**
     * Creates a result that requires manual admin review before the step can pass or fail.
     */
    public static VerificationStepResult pendingReview(Map<String, Object> resultData) {
        return new VerificationStepResult(false, null, resultData, "PENDING_REVIEW");
    }
}
