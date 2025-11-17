package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUser(User user);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user AND rt.isRevoked = false AND rt.expiryDate > :now")
    List<RefreshToken> findActiveTokensByUser(User user, Instant now);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.isRevoked = true, rt.revokedAt = :revokedAt WHERE rt.user = :user AND rt.isRevoked = false")
    int revokeAllUserTokens(User user, Instant revokedAt);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :expiryDate")
    int deleteExpiredTokens(Instant expiryDate);

    boolean existsByTokenAndIsRevokedFalse(String token);
}
