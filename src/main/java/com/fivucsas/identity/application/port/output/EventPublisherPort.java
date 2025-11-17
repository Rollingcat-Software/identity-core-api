package com.fivucsas.identity.application.port.output;

/**
 * Output port for publishing domain events.
 *
 * This interface defines the contract for publishing domain events
 * to other parts of the system or external services.
 * Currently a placeholder for future implementation.
 *
 * Following principles:
 * - Dependency Inversion: Application defines the port, infrastructure implements
 * - Interface Segregation: Only event publishing
 * - Event-Driven Architecture: Enables loose coupling
 *
 * NOTE: This is a placeholder for Phase 4 implementation.
 */
public interface EventPublisherPort {

    /**
     * Publishes a user registered event.
     *
     * @param userId the user ID
     * @param email the user email
     */
    void publishUserRegistered(String userId, String email);

    /**
     * Publishes a user authenticated event.
     *
     * @param userId the user ID
     * @param email the user email
     */
    void publishUserAuthenticated(String userId, String email);

    /**
     * Publishes a biometric enrolled event.
     *
     * @param userId the user ID
     */
    void publishBiometricEnrolled(String userId);

    /**
     * Publishes a biometric verified event.
     *
     * @param userId the user ID
     * @param success whether verification was successful
     */
    void publishBiometricVerified(String userId, boolean success);
}
