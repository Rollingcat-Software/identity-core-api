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
     * Sums the verification count across all users.
     * Used for statistics.
     *
     * @return total verification count
     */
    Long sumVerificationCount();

    /**
     * Saves a user.
     * @param user the user to save
     * @return the saved user
     */
    <S extends User> S save(S user);

    /**
     * Finds a user by ID.
     * @param id the ID of the user
     * @return Optional containing the user if found
     */
    Optional<User> findById(UUID id);

    /**
     * Finds all users.
     * @return list of all users
     */
    List<User> findAll();

    /**
     * Counts all users.
     * @return total count of users
     */
    long count();

    /**
     * Deletes a user.
     * @param user the user to delete
     */
    void delete(User user);

    Optional<User> findByPasswordResetToken(String token);

    Optional<User> findByEmailVerificationToken(String token);
}
