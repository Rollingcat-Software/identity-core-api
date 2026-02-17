package com.fivucsas.identity.repository;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.entity.AuthSession;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT s FROM AuthSession s WHERE s.id = :id")
    Optional<AuthSession> findByIdForUpdate(UUID id);

    Optional<AuthSession> findByIdAndTenantId(UUID id, UUID tenantId);
    List<AuthSession> findAllByUserIdAndStatus(UUID userId, AuthSessionStatus status);
    List<AuthSession> findAllByExpiresAtBeforeAndStatusIn(Instant now, List<AuthSessionStatus> statuses);
}
