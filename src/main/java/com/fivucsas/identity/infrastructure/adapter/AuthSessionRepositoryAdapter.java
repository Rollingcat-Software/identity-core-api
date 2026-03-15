package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuthSessionRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthSessionStatus;
import com.fivucsas.identity.entity.AuthSession;
import com.fivucsas.identity.repository.AuthSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class AuthSessionRepositoryAdapter implements AuthSessionRepositoryPort {

    private final AuthSessionRepository jpaRepository;

    @Override
    public Optional<AuthSession> findByIdForUpdate(UUID id) {
        return jpaRepository.findByIdForUpdate(id);
    }

    @Override
    public Optional<AuthSession> findByIdAndTenantId(UUID id, UUID tenantId) {
        return jpaRepository.findByIdAndTenantId(id, tenantId);
    }

    @Override
    public Optional<AuthSession> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public List<AuthSession> findAllByUserIdAndStatus(UUID userId, AuthSessionStatus status) {
        return jpaRepository.findAllByUserIdAndStatus(userId, status);
    }

    @Override
    public List<AuthSession> findAllByExpiresAtBeforeAndStatusIn(Instant now, List<AuthSessionStatus> statuses) {
        return jpaRepository.findAllByExpiresAtBeforeAndStatusIn(now, statuses);
    }

    @Override
    public AuthSession save(AuthSession session) {
        return jpaRepository.save(session);
    }
}
