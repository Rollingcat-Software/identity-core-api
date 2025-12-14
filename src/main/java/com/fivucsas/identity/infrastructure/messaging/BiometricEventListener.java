package com.fivucsas.identity.infrastructure.messaging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Event listener for biometric processing events.
 *
 * <p>This component listens to events published by the biometric-processor service
 * and handles them according to the event type.
 *
 * <p><strong>Event Flow:</strong>
 * <ol>
 *   <li>User requests enrollment/verification via identity-core-api</li>
 *   <li>API publishes "requested" event</li>
 *   <li>Biometric processor subscribes and processes</li>
 *   <li>Processor publishes "completed" or "failed" event</li>
 *   <li>This listener receives and handles the result</li>
 * </ol>
 *
 * <p><strong>Following SOLID Principles:</strong>
 * <ul>
 *   <li>Single Responsibility: Only handles event processing</li>
 *   <li>Open/Closed: Easy to extend with new event types</li>
 * </ul>
 *
 * @author FIVUCSAS Team
 * @version 1.0
 * @since 2025
 */
@Component
public class BiometricEventListener {

    private static final Logger logger = LoggerFactory.getLogger(BiometricEventListener.class);

    private int processedEvents = 0;

    /**
     * Constructs a BiometricEventListener.
     */
    public BiometricEventListener() {
        logger.info("BiometricEventListener initialized");
    }

    /**
     * Handles incoming biometric events.
     *
     * <p>Routes events to appropriate handler methods based on event_type field.
     *
     * @param event Event data containing event_type and payload
     */
    public void onEvent(Map<String, Object> event) {
        String eventType = (String) event.get("event_type");

        if (eventType == null) {
            logger.warn("Received event without event_type field");
            return;
        }

        try {
            switch (eventType) {
                case "enrollment.started":
                    handleEnrollmentStarted(event);
                    break;
                case "enrollment.completed":
                    handleEnrollmentCompleted(event);
                    break;
                case "enrollment.failed":
                    handleEnrollmentFailed(event);
                    break;
                case "verification.started":
                    handleVerificationStarted(event);
                    break;
                case "verification.completed":
                    handleVerificationCompleted(event);
                    break;
                case "verification.failed":
                    handleVerificationFailed(event);
                    break;
                case "liveness.check.completed":
                    handleLivenessCheckCompleted(event);
                    break;
                case "quality.assessment.completed":
                    handleQualityAssessmentCompleted(event);
                    break;
                default:
                    logger.debug("No handler registered for event type: {}", eventType);
            }

            processedEvents++;

        } catch (Exception e) {
            logger.error("Error handling event type '{}': {}", eventType, e.getMessage(), e);
        }
    }

    /**
     * Handles enrollment started events.
     *
     * @param event Event data
     */
    private void handleEnrollmentStarted(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        String correlationId = (String) event.get("correlation_id");

        logger.info(
                "Enrollment started: user_id={}, correlation_id={}",
                userId,
                correlationId
        );

        // Here you would:
        // 1. Update user enrollment status in database
        // 2. Send real-time notification to client
        // 3. Log to analytics
    }

    /**
     * Handles enrollment completed events.
     *
     * @param event Event data
     */
    private void handleEnrollmentCompleted(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        String faceId = (String) event.get("face_id");
        Object qualityScore = event.get("quality_score");
        Object processingTime = event.get("processing_time_ms");

        logger.info(
                "Enrollment completed: user_id={}, face_id={}, quality_score={}, processing_time_ms={}",
                userId,
                faceId,
                qualityScore,
                processingTime
        );

        // Here you would:
        // 1. Update user status to ENROLLED in database
        // 2. Store face_id reference
        // 3. Send success notification to user
        // 4. Update metrics and analytics
        // 5. Trigger next workflow steps if needed
    }

    /**
     * Handles enrollment failed events.
     *
     * @param event Event data
     */
    private void handleEnrollmentFailed(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        String errorMessage = (String) event.get("error_message");

        logger.warn(
                "Enrollment failed: user_id={}, error={}",
                userId,
                errorMessage
        );

        // Here you would:
        // 1. Update user status to ENROLLMENT_FAILED
        // 2. Store error details for debugging
        // 3. Send failure notification to user
        // 4. Log to error monitoring system
        // 5. Trigger retry logic if applicable
    }

    /**
     * Handles verification started events.
     *
     * @param event Event data
     */
    private void handleVerificationStarted(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        String faceId = (String) event.get("face_id");

        logger.info(
                "Verification started: user_id={}, face_id={}",
                userId,
                faceId
        );

        // Here you would:
        // 1. Log verification attempt
        // 2. Update rate limiting counters
        // 3. Check for suspicious patterns
    }

    /**
     * Handles verification completed events.
     *
     * @param event Event data
     */
    private void handleVerificationCompleted(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        Boolean isMatch = (Boolean) event.get("is_match");
        Object similarityScore = event.get("similarity_score");
        Object livenessScore = event.get("liveness_score");
        Object processingTime = event.get("processing_time_ms");

        logger.info(
                "Verification completed: user_id={}, is_match={}, similarity={}, liveness={}, processing_time_ms={}",
                userId,
                isMatch,
                similarityScore,
                livenessScore,
                processingTime
        );

        // Here you would:
        // 1. Update authentication session
        // 2. Grant or deny access based on is_match
        // 3. Log authentication event
        // 4. Send result notification
        // 5. Update security metrics
        // 6. Detect fraud patterns
    }

    /**
     * Handles verification failed events.
     *
     * @param event Event data
     */
    private void handleVerificationFailed(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        String errorMessage = (String) event.get("error_message");

        logger.warn(
                "Verification failed: user_id={}, error={}",
                userId,
                errorMessage
        );

        // Here you would:
        // 1. Log security event
        // 2. Update fraud detection system
        // 3. Send failure notification
        // 4. Increment failed attempt counter
        // 5. Trigger account lockout if threshold exceeded
    }

    /**
     * Handles liveness check completed events.
     *
     * @param event Event data
     */
    private void handleLivenessCheckCompleted(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        Boolean isLive = (Boolean) event.get("is_live");
        Object livenessScore = event.get("liveness_score");
        String technique = (String) event.get("technique");

        logger.info(
                "Liveness check completed: user_id={}, is_live={}, score={}, technique={}",
                userId,
                isLive,
                livenessScore,
                technique
        );

        // Here you would:
        // 1. Log anti-spoofing metrics
        // 2. Update security dashboards
        // 3. Trigger alerts for suspected spoofing
    }

    /**
     * Handles quality assessment completed events.
     *
     * @param event Event data
     */
    private void handleQualityAssessmentCompleted(Map<String, Object> event) {
        String userId = (String) event.get("user_id");
        Object qualityScore = event.get("quality_score");
        Boolean isAcceptable = (Boolean) event.get("is_acceptable");

        logger.info(
                "Quality assessment completed: user_id={}, score={}, acceptable={}",
                userId,
                qualityScore,
                isAcceptable
        );

        // Here you would:
        // 1. Log quality metrics
        // 2. Provide feedback to users on image quality
        // 3. Update ML model training data
    }

    /**
     * Gets the number of processed events.
     *
     * @return Total number of events processed
     */
    public int getProcessedEventCount() {
        return processedEvents;
    }
}
