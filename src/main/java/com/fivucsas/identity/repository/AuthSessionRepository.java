package com.fivucsas.identity.repository;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.entity.AuthSession;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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

    // --- Admin list endpoint (PR feat/auth-sessions-admin-list) ---

    /**
     * Paginated tenant-scoped list of auth sessions, optionally filtered by
     * status. Used by {@code GET /api/v1/auth/sessions} admin endpoint.
     */
    Page<AuthSession> findAllByTenantIdAndStatusIn(
            UUID tenantId, List<AuthSessionStatus> statuses, Pageable pageable);

    /**
     * Same as above but unfiltered by status — returns every session for the
     * tenant. Used when caller passes no status filter.
     */
    Page<AuthSession> findAllByTenantId(UUID tenantId, Pageable pageable);

    /**
     * Tenant + user + status — used when admin drills into a specific user's
     * sessions.
     */
    Page<AuthSession> findAllByTenantIdAndUserIdAndStatusIn(
            UUID tenantId, UUID userId, List<AuthSessionStatus> statuses, Pageable pageable);

    Page<AuthSession> findAllByTenantIdAndUserId(UUID tenantId, UUID userId, Pageable pageable);
}
