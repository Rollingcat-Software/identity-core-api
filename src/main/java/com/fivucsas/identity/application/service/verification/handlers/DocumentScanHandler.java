package com.fivucsas.identity.application.service.verification.handlers;

import com.fivucsas.identity.application.service.verification.VerificationStepHandler;
import com.fivucsas.identity.application.service.verification.VerificationStepResult;
import com.fivucsas.identity.entity.VerificationSession;
import com.fivucsas.identity.infrastructure.adapter.BiometricProcessorClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Handles DOCUMENT_SCAN verification step.
 * Delegates to biometric-processor for document classification.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DocumentScanHandler implements VerificationStepHandler {

    private final BiometricProcessorClient processorClient;

    @Override
    public String getStepType() {
        return "DOCUMENT_SCAN";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String image = (String) data.get("image");
        if (image == null || image.isBlank()) {
            return VerificationStepResult.failure("Document image is required");
        }

        try {
            Map<String, Object> response = processorClient.documentScan(image);

            // Check for client-side error responses from BiometricProcessorClient
            if (Boolean.FALSE.equals(response.get("success"))) {
                String error = (String) response.getOrDefault("error", "Document scan failed");
                return VerificationStepResult.failure(error);
            }

            // Biometric-processor returns: detected, card_type, confidence, bounding_box
            boolean detected = Boolean.TRUE.equals(response.get("detected"));
            if (!detected) {
                return VerificationStepResult.failure("No document detected in the image");
            }

            String documentType = (String) response.getOrDefault("card_type", "UNKNOWN");
            Double confidence = parseDouble(response.get("confidence"));

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("document_type", documentType);
            resultData.put("confidence", confidence);
            resultData.put("session_id", session.getId().toString());
            if (response.containsKey("cropped_document_image_base64")) {
                resultData.put("cropped_image", response.get("cropped_document_image_base64"));
            }

            log.info("Document scan completed for session {}: type={}, confidence={}",
                    session.getId(), documentType, confidence);
            return VerificationStepResult.success(confidence, resultData);
        } catch (Exception e) {
            log.error("Document scan error for session {}: {}", session.getId(), e.getMessage(), e);
            return VerificationStepResult.failure("Document scan service unavailable");
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
