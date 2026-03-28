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
 * Handles VIDEO_INTERVIEW verification step.
 * Records a short video from the user and stores it for manual admin review.
 * The step stays in PENDING_REVIEW until an admin approves or rejects it.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class VideoInterviewHandler implements VerificationStepHandler {

    private final BiometricProcessorClient processorClient;

    @Override
    public String getStepType() {
        return "VIDEO_INTERVIEW";
    }

    @Override
    public VerificationStepResult execute(VerificationSession session, int stepNumber, Map<String, Object> data) {
        String videoData = (String) data.get("video");
        String mimeType = (String) data.getOrDefault("mime_type", "video/webm");

        if (videoData == null || videoData.isBlank()) {
            return VerificationStepResult.failure("Video recording data is required");
        }

        // Validate mime type
        if (!"video/webm".equals(mimeType) && !"video/mp4".equals(mimeType)) {
            return VerificationStepResult.failure("Unsupported video format. Accepted: video/webm, video/mp4");
        }

        try {
            Map<String, Object> response = processorClient.videoInterviewUpload(videoData, mimeType);

            if (Boolean.FALSE.equals(response.get("stored"))) {
                String error = (String) response.getOrDefault("error", "Video upload failed");
                return VerificationStepResult.failure(error);
            }

            // Check for client-side error from BiometricProcessorClient
            if (Boolean.FALSE.equals(response.get("success"))) {
                String error = (String) response.getOrDefault("error", "Video upload failed");
                return VerificationStepResult.failure(error);
            }

            Map<String, Object> resultData = new HashMap<>();
            resultData.put("status", "PENDING_REVIEW");
            resultData.put("filename", response.get("filename"));
            resultData.put("duration_seconds", response.get("duration_seconds"));
            resultData.put("stored", true);

            log.info("Video interview uploaded for session {}. Stored as '{}'. Awaiting admin review.",
                    session.getId(), response.get("filename"));

            return VerificationStepResult.pendingReview(resultData);
        } catch (Exception e) {
            log.error("Video interview upload error for session {}: {}", session.getId(), e.getMessage(), e);
            return VerificationStepResult.failure("Video interview service unavailable");
        }
    }
}
