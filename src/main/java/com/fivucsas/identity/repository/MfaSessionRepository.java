package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.MfaSession;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface MfaSessionRepository extends JpaRepository<MfaSession, UUID> {

    Optional<MfaSession> findBySessionToken(String sessionToken);

    /**
     * Pessimistic-lock variant for the /auth/mfa/step path. Two parallel
     * correct OTP submissions in the same session window would otherwise
     * race the read-validate-write block in AuthController.verifyMfaStep
     * and could double-credit completedMethods, advancing currentStep
     * twice. The row lock serializes them. Closes audit-edge 2026-04-28
     * P0 finding #1.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT m FROM MfaSession m WHERE m.sessionToken = :sessionToken")
    Optional<MfaSession> findBySessionTokenForUpdate(@Param("sessionToken") String sessionToken);

    /**
     * Cleanup query for expired, never-completed MFA sessions.
     *
     * <p>Uses {@code <= :now} (inclusive) to match the boundary semantics of
     * {@link com.fivucsas.identity.entity.MfaSession#isExpired()}, which uses
     * {@code !expiresAt.isAfter(now)} — i.e. a session whose expiresAt equals
     * the current instant is treated as expired. Edge-P2 #6, 2026-04-29.
     */
    @Modifying
    @Query("DELETE FROM MfaSession m WHERE m.expiresAt <= :now AND m.completedAt IS NULL")
    int deleteExpiredSessions(Instant now);
}
