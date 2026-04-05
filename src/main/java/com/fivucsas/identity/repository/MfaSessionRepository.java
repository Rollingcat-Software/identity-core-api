package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.MfaSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface MfaSessionRepository extends JpaRepository<MfaSession, UUID> {

    Optional<MfaSession> findBySessionToken(String sessionToken);

    @Modifying
    @Query("DELETE FROM MfaSession m WHERE m.expiresAt < :now AND m.completedAt IS NULL")
    int deleteExpiredSessions(Instant now);
}
