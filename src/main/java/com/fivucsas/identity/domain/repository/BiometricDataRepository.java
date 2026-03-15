package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.entity.BiometricData;
import com.fivucsas.identity.entity.User;

import java.util.List;
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
     * Finds all biometric data records.
     */
    List<BiometricData> findAll();

    /**
     * Finds biometric data by ID.
     */
    Optional<BiometricData> findById(UUID id);

    /**
     * Deletes a specific biometric data record.
     * Named distinctly from CrudRepository.delete(T) to avoid ambiguity.
     *
     * @param data the biometric data to delete
     */
    void deleteRecord(BiometricData data);

    /**
     * Deletes biometric data for a user.
     *
     * @param user the user
     */
    void deleteByUser(User user);
}
