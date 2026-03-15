package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuthSessionStepRepositoryPort;
import com.fivucsas.identity.entity.AuthSessionStep;
import com.fivucsas.identity.repository.AuthSessionStepRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class AuthSessionStepRepositoryAdapter implements AuthSessionStepRepositoryPort {

    private final AuthSessionStepRepository jpaRepository;

    @Override
    public List<AuthSessionStep> findAllBySessionId(UUID sessionId) {
        return jpaRepository.findAllBySessionId(sessionId);
    }

    @Override
    public Optional<AuthSessionStep> findBySessionIdAndAuthFlowStepId(UUID sessionId, UUID flowStepId) {
        return jpaRepository.findBySessionIdAndAuthFlowStepId(sessionId, flowStepId);
    }

    @Override
    public Optional<AuthSessionStep> findByDelegationToken(String token) {
        return jpaRepository.findByDelegationToken(token);
    }

    @Override
    public AuthSessionStep save(AuthSessionStep step) {
        return jpaRepository.save(step);
    }
}
