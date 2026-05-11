package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * JPA Repository for RefreshToken entity.
 *
 * Implements domain repository contract + JPA features.
 * Following Dependency Inversion Principle.
 */
@Repository
public interface RefreshTokenRepository extends
        JpaRepository<RefreshToken, UUID>,
        com.fivucsas.identity.domain.repository.RefreshTokenRepository {

    // Note (T4-D, 2026-05-11): {@code findByToken(String)} and
    // {@code existsByTokenAndIsRevokedFalse(String)} were derived queries that
    // resolved against {@code refresh_tokens.token} (the plaintext column).
    // V60 dropped that column; lookups now go by id +
    // {@code token_secret_hash} via {@code RefreshTokenService.findByToken}.
    // Leaving these methods in place would cause Hibernate metadata
    // validation to fail at boot.

    List<RefreshToken> findByUser(User user);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user AND rt.isRevoked = false AND rt.expiryDate > :now")
    List<RefreshToken> findActiveTokensByUser(User user, Instant now);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true, rt.revokedAt = :revokedAt WHERE rt.user = :user AND rt.isRevoked = false")
    int revokeAllUserTokens(User user, Instant revokedAt);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :expiryDate")
    int deleteExpiredTokens(Instant expiryDate);

    // existsByTokenAndIsRevokedFalse removed by T4-D — see note above.

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true, rt.revokedAt = :revokedAt WHERE rt.user = :user AND rt.id = :tokenId AND rt.isRevoked = false")
    int revokeUserToken(User user, UUID tokenId, Instant revokedAt);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true, rt.revokedAt = :revokedAt WHERE rt.user = :user AND rt.id != :currentTokenId AND rt.isRevoked = false")
    int revokeAllUserTokensExceptCurrent(User user, UUID currentTokenId, Instant revokedAt);

    /**
     * Bulk-revoke every refresh token belonging to the given rotation family.
     *
     * <p>Reuse-detection path (Sec-P2 #6): when the rotation endpoint sees a
     * presented token that is already revoked, every token in the family —
     * including any active descendant minted by the attacker who "won" the
     * race — must be revoked at once. RFC 6749 §10.4 + OAuth 2.0 Security
     * BCP §4.13.
     *
     * <p>Returns the number of rows updated. Already-revoked rows are
     * skipped by the {@code rt.isRevoked = false} guard so this is safe to
     * call repeatedly.
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true, rt.revokedAt = :revokedAt " +
            "WHERE rt.familyId = :familyId AND rt.isRevoked = false")
    int revokeFamily(UUID familyId, Instant revokedAt);
}
