package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.domain.model.user.Email;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Domain repository interface for User aggregate.
 *
 * Following principles:
 * - Dependency Inversion: Domain defines the contract
 * - Interface Segregation: Only domain-relevant operations
 * - Abstraction: No persistence details leaked
 *
 * Implementation is in infrastructure layer (JPA).
 */
public interface UserRepository {

    /**
     * Saves a user (create or update).
     *
     * @param user the user to save
     * @return the saved user
     */
    User save(User user);

    /**
     * Finds a user by their unique identifier.
     *
     * @param id the user ID
     * @return Optional containing the user if found
     */
    Optional<User> findById(UUID id);

    /**
     * Finds a user by their email address.
     *
     * @param email the email to search for
     * @return Optional containing the user if found
     */
    Optional<User> findByEmail(String email);

    /**
     * Checks if a user with the given email exists.
     *
     * @param email the email to check
     * @return true if user exists
     */
    boolean existsByEmail(String email);

    /**
     * Finds all users with a specific status.
     *
     * @param status the user status
     * @return list of users with the status
     */
    List<User> findByStatus(UserStatus status);

    /**
     * Counts users with a specific status.
     *
     * @param status the user status
     * @return count of users
     */
    long countByStatus(UserStatus status);

    /**
     * Counts users who have enrolled biometric data.
     *
     * @param enrolled true to count enrolled users
     * @return count of users
     */
    long countByIsBiometricEnrolled(boolean enrolled);

    /**
     * Searches users by query (name, email, or ID number).
     *
     * @param query the search query
     * @return list of matching users
     */
    List<User> searchUsers(String query);

    /**
     * Finds all users.
     *
     * @return list of all users
     */
    List<User> findAll();

    /**
     * Deletes a user.
     *
     * @param user the user to delete
     */
    void delete(User user);

    /**
     * Counts total number of users.
     *
     * @return total user count
     */
    long count();

    /**
     * Sums the verification count across all users.
     * Used for statistics.
     *
     * @return total verification count
     */
    Long sumVerificationCount();
}
