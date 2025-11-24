package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;

import java.util.Optional;
import java.util.UUID;

/**
 * Domain repository interface for BiometricData entity.
 *
 * Following principles:
 * - Dependency Inversion: Domain defines the contract
 * - Interface Segregation: Only biometric operations
 * - Abstraction: No persistence details
 */
public interface BiometricDataRepository {

    /**
     * Finds biometric data by user.
     *
     * @param user the user
     * @return Optional containing biometric data if found
     */
    Optional<BiometricData> findByUser(User user);

    /**
     * Finds biometric data by user ID.
     *
     * @param userId the user ID
     * @return Optional containing biometric data if found
     */
    Optional<BiometricData> findByUserId(UUID userId);

    /**
     * Deletes biometric data for a user.
     *
     * @param user the user
     */
    void deleteByUser(User user);
}
