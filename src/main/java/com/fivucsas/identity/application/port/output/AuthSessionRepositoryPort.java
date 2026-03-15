package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.entity.AuthSession;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for AuthSession persistence operations.
 */
public interface AuthSessionRepositoryPort {

    Optional<AuthSession> findByIdForUpdate(UUID id);

    Optional<AuthSession> findByIdAndTenantId(UUID id, UUID tenantId);

    Optional<AuthSession> findById(UUID id);

    List<AuthSession> findAllByUserIdAndStatus(UUID userId, AuthSessionStatus status);

    List<AuthSession> findAllByExpiresAtBeforeAndStatusIn(Instant now, List<AuthSessionStatus> statuses);

    AuthSession save(AuthSession session);
}
