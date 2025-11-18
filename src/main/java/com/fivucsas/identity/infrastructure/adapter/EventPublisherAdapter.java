package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.EventPublisherPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Infrastructure adapter for event publishing.
 *
 * Implements the EventPublisherPort using simple logging for now.
 * In production, this should publish to a message queue (Kafka, RabbitMQ, etc.)
 * or use Spring's ApplicationEventPublisher.
 *
 * NOTE: This is a placeholder implementation for Phase 4.
 *
 * Following principles:
 * - Adapter Pattern: Adapts event publishing to our port
 * - Dependency Inversion: Application defines port, infrastructure implements
 * - Event-Driven Architecture: Enables loose coupling
 */
@Component
@Slf4j
public class EventPublisherAdapter implements EventPublisherPort {

    @Override
    public void publishUserRegistered(String userId, String email) {
        log.info("EVENT: UserRegistered - userId={}, email={}", userId, email);
        // TODO: Publish to message queue in Phase 4
    }

    @Override
    public void publishUserAuthenticated(String userId, String email) {
        log.info("EVENT: UserAuthenticated - userId={}, email={}", userId, email);
        // TODO: Publish to message queue in Phase 4
    }

    @Override
    public void publishBiometricEnrolled(String userId) {
        log.info("EVENT: BiometricEnrolled - userId={}", userId);
        // TODO: Publish to message queue in Phase 4
    }

    @Override
    public void publishBiometricVerified(String userId, boolean success) {
        log.info("EVENT: BiometricVerified - userId={}, success={}", userId, success);
        // TODO: Publish to message queue in Phase 4
    }
}
