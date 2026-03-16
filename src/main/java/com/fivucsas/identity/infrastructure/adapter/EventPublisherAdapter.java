package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.EventPublisherPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Infrastructure adapter for event publishing.
 *
 * Uses Spring's ApplicationEventPublisher for in-process event distribution.
 * Events can be consumed by @EventListener methods for audit logging,
 * notifications, etc. Future migration to Kafka/RabbitMQ can be done
 * by adding a bridge listener.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class EventPublisherAdapter implements EventPublisherPort {

    private final ApplicationEventPublisher eventPublisher;

    @Override
    public void publishUserRegistered(String userId, String email) {
        log.info("EVENT: UserRegistered - userId={}, email={}", userId, email);
        eventPublisher.publishEvent(new UserRegisteredEvent(userId, email));
    }

    @Override
    public void publishUserAuthenticated(String userId, String email) {
        log.info("EVENT: UserAuthenticated - userId={}, email={}", userId, email);
        eventPublisher.publishEvent(new UserAuthenticatedEvent(userId, email));
    }

    @Override
    public void publishBiometricEnrolled(String userId) {
        log.info("EVENT: BiometricEnrolled - userId={}", userId);
        eventPublisher.publishEvent(new BiometricEnrolledEvent(userId));
    }

    @Override
    public void publishBiometricVerified(String userId, boolean success) {
        log.info("EVENT: BiometricVerified - userId={}, success={}", userId, success);
        eventPublisher.publishEvent(new BiometricVerifiedEvent(userId, success));
    }

    public record UserRegisteredEvent(String userId, String email) {}
    public record UserAuthenticatedEvent(String userId, String email) {}
    public record BiometricEnrolledEvent(String userId) {}
    public record BiometricVerifiedEvent(String userId, boolean success) {}
}
