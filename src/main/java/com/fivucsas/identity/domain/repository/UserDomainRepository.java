package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.domain.model.user.User;
import com.fivucsas.identity.domain.model.user.UserStatus;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Pure domain repository interface for User aggregate.
 * Returns domain model objects only - no JPA entity leakage.
 *
 * This is the target interface for new code following Hexagonal Architecture.
 * The existing UserRepository (returning JPA entities) remains for backward compatibility.
 *
 * Implementation: infrastructure/adapter/UserDomainRepositoryAdapter
 */
public interface UserDomainRepository {

    /**
     * Saves a domain user (create or update).
     * Converts to JPA entity internally for persistence.
     */
    User save(User user);

    /**
     * Finds a user by ID, returning domain model.
     */
    Optional<User> findById(UUID id);

    /**
     * Finds a user by email, returning domain model.
     */
    Optional<User> findByEmail(String email);

    /**
     * Checks if a user with the given email exists.
     */
    boolean existsByEmail(String email);

    /**
     * Finds all users with a specific status.
     */
    List<User> findByStatus(UserStatus status);

    /**
     * Counts users with a specific status (uses domain UserStatus).
     */
    long countByStatus(UserStatus status);

    /**
     * Counts users who have enrolled biometric data.
     */
    long countByIsBiometricEnrolled(boolean enrolled);

    /**
     * Finds all users with the given {@code is_biometric_enrolled} flag value,
     * returning domain models. Backs the biometric-enrollment reconciler, which
     * scans users flagged {@code false} for ones that actually have a bio-store
     * embedding (the "enrolled-but-412" repair).
     */
    List<User> findByIsBiometricEnrolled(boolean enrolled);

    /**
     * Searches users by query (name, email, or ID number).
     */
    List<User> searchUsers(String query);

    /**
     * Sums the verification count across all users.
     */
    Long sumVerificationCount();

    /**
     * Finds all users.
     */
    List<User> findAll();

    /**
     * Finds users with pagination.
     */
    List<User> findAll(int page, int size);

    /**
     * Counts all users.
     */
    long count();

    /**
     * Deletes a user by ID.
     */
    void deleteById(UUID id);

    /**
     * Finds a user by password reset token.
     */
    Optional<User> findByPasswordResetToken(String token);

    /**
     * Finds a user by email verification token.
     */
    Optional<User> findByEmailVerificationToken(String token);

    /**
     * Finds users whose guest access has expired.
     */
    List<User> findExpiredGuests(Instant now);
}
