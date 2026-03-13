package com.fivucsas.identity.domain.repository;

import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Domain repository interface for RefreshToken entity.
 *
 * Following principles:
 * - Dependency Inversion: Domain defines the contract
 * - Interface Segregation: Only token-related operations
 * - Abstraction: No JPA-specific details
 */
public interface RefreshTokenRepository {

    /**
     * Finds a refresh token by its token string.
     *
     * @param token the token string
     * @return Optional containing the token if found
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Finds all refresh tokens for a user.
     *
     * @param user the user
     * @return list of tokens
     */
    List<RefreshToken> findByUser(User user);

    /**
     * Finds active (non-revoked, non-expired) tokens for a user.
     *
     * @param user the user
     * @param now current timestamp
     * @return list of active tokens
     */
    List<RefreshToken> findActiveTokensByUser(User user, Instant now);

    /**
     * Revokes all tokens for a user.
     *
     * @param user the user
     * @param revokedAt timestamp of revocation
     * @return number of tokens revoked
     */
    int revokeAllUserTokens(User user, Instant revokedAt);

    /**
     * Deletes expired tokens.
     * Used for cleanup/maintenance.
     *
     * @param expiryDate tokens older than this are deleted
     * @return number of tokens deleted
     */
    int deleteExpiredTokens(Instant expiryDate);

    /**
     * Checks if a non-revoked token exists.
     *
     * @param token the token string
     * @return true if active token exists
     */
    boolean existsByTokenAndIsRevokedFalse(String token);

    int revokeUserToken(User user, UUID tokenId, Instant revokedAt);

    int revokeAllUserTokensExceptCurrent(User user, UUID currentTokenId, Instant revokedAt);
}
