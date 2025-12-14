package com.fivucsas.identity.infrastructure.messaging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service for publishing biometric events to the event bus.
 *
 * <p>This service provides a high-level API for publishing events from application services
 * without coupling them directly to the Redis event bus implementation.
 *
 * <p><strong>Following Facade Pattern:</strong>
 * <ul>
 *   <li>Simplifies event publishing for business logic</li>
 *   <li>Provides a clean interface for event publication</li>
 *   <li>Handles event structure and serialization</li>
 * </ul>
 *
 * <p><strong>Event Channels:</strong>
 * <ul>
 *   <li>biometric.enrollment - Enrollment events</li>
 *   <li>biometric.verification - Verification events</li>
 *   <li>biometric.liveness - Liveness detection events</li>
 *   <li>biometric.quality - Quality assessment events</li>
 * </ul>
 *
 * @author FIVUCSAS Team
 * @version 1.0
 * @since 2025
 */
@Service
public class BiometricEventPublisher {

    private static final Logger logger = LoggerFactory.getLogger(BiometricEventPublisher.class);

    private static final String CHANNEL_ENROLLMENT = "biometric.enrollment";
    private static final String CHANNEL_VERIFICATION = "biometric.verification";
    private static final String CHANNEL_LIVENESS = "biometric.liveness";
    private static final String CHANNEL_QUALITY = "biometric.quality";

    private final RedisEventBus eventBus;
    private final boolean enabled;

    /**
     * Constructs a BiometricEventPublisher.
     *
     * @param eventBus Redis event bus for publishing
     */
    public BiometricEventPublisher(RedisEventBus eventBus) {
        this.eventBus = eventBus;
        this.enabled = eventBus != null;
        logger.info("BiometricEventPublisher initialized (enabled={})", enabled);
    }

    /**
     * Publishes an enrollment requested event.
     *
     * @param userId User ID
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishEnrollmentRequested(String userId, String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "enrollment.requested",
                userId,
                correlationId,
                "normal"
        );

        return eventBus.publish(CHANNEL_ENROLLMENT, event);
    }

    /**
     * Publishes an enrollment started event.
     *
     * @param userId User ID
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishEnrollmentStarted(String userId, String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "enrollment.started",
                userId,
                correlationId,
                "normal"
        );

        return eventBus.publish(CHANNEL_ENROLLMENT, event);
    }

    /**
     * Publishes an enrollment completed event.
     *
     * @param userId User ID
     * @param faceId Face ID
     * @param qualityScore Image quality score
     * @param embeddingDimension Embedding dimension
     * @param processingTimeMs Processing time in milliseconds
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishEnrollmentCompleted(
            String userId,
            String faceId,
            Double qualityScore,
            Integer embeddingDimension,
            Double processingTimeMs,
            String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "enrollment.completed",
                userId,
                correlationId,
                "high"
        );

        event.put("face_id", faceId);
        event.put("quality_score", qualityScore);
        event.put("embedding_dimension", embeddingDimension);
        event.put("processing_time_ms", processingTimeMs);
        event.put("success", true);

        return eventBus.publish(CHANNEL_ENROLLMENT, event);
    }

    /**
     * Publishes an enrollment failed event.
     *
     * @param userId User ID
     * @param errorMessage Error description
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishEnrollmentFailed(
            String userId,
            String errorMessage,
            String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "enrollment.failed",
                userId,
                correlationId,
                "high"
        );

        event.put("success", false);
        event.put("error_message", errorMessage);

        return eventBus.publish(CHANNEL_ENROLLMENT, event);
    }

    /**
     * Publishes a verification requested event.
     *
     * @param userId User ID
     * @param faceId Face ID to verify against
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishVerificationRequested(
            String userId,
            String faceId,
            String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "verification.requested",
                userId,
                correlationId,
                "normal"
        );

        event.put("face_id", faceId);

        return eventBus.publish(CHANNEL_VERIFICATION, event);
    }

    /**
     * Publishes a verification started event.
     *
     * @param userId User ID
     * @param faceId Face ID to verify against
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishVerificationStarted(
            String userId,
            String faceId,
            String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "verification.started",
                userId,
                correlationId,
                "normal"
        );

        event.put("face_id", faceId);

        return eventBus.publish(CHANNEL_VERIFICATION, event);
    }

    /**
     * Publishes a verification completed event.
     *
     * @param userId User ID
     * @param faceId Face ID verified against
     * @param isMatch Whether verification succeeded
     * @param similarityScore Similarity score
     * @param threshold Threshold used
     * @param confidence Confidence level
     * @param livenessScore Liveness score if checked
     * @param processingTimeMs Processing time in milliseconds
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishVerificationCompleted(
            String userId,
            String faceId,
            Boolean isMatch,
            Double similarityScore,
            Double threshold,
            Double confidence,
            Double livenessScore,
            Double processingTimeMs,
            String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "verification.completed",
                userId,
                correlationId,
                "high"
        );

        event.put("face_id", faceId);
        event.put("is_match", isMatch);
        event.put("similarity_score", similarityScore);
        event.put("threshold", threshold);
        event.put("confidence", confidence);
        event.put("liveness_score", livenessScore);
        event.put("processing_time_ms", processingTimeMs);

        return eventBus.publish(CHANNEL_VERIFICATION, event);
    }

    /**
     * Publishes a verification failed event.
     *
     * @param userId User ID
     * @param faceId Face ID
     * @param errorMessage Error description
     * @param correlationId Correlation ID for tracking
     * @return true if published successfully
     */
    public boolean publishVerificationFailed(
            String userId,
            String faceId,
            String errorMessage,
            String correlationId) {
        if (!enabled) {
            return false;
        }

        Map<String, Object> event = createBaseEvent(
                "verification.failed",
                userId,
                correlationId,
                "high"
        );

        event.put("face_id", faceId);
        event.put("error_message", errorMessage);

        return eventBus.publish(CHANNEL_VERIFICATION, event);
    }

    /**
     * Creates a base event structure with common fields.
     *
     * @param eventType Type of the event
     * @param userId User ID
     * @param correlationId Correlation ID
     * @param priority Event priority
     * @return Event map with base fields
     */
    private Map<String, Object> createBaseEvent(
            String eventType,
            String userId,
            String correlationId,
            String priority) {
        Map<String, Object> event = new HashMap<>();

        event.put("event_id", UUID.randomUUID().toString());
        event.put("event_type", eventType);
        event.put("timestamp", Instant.now().toString());
        event.put("user_id", userId);
        event.put("correlation_id", correlationId);
        event.put("priority", priority);
        event.put("metadata", new HashMap<>());

        return event;
    }

    /**
     * Checks if the event publisher is enabled.
     *
     * @return true if enabled, false otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }
}
