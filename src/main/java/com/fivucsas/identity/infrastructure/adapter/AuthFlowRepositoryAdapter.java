package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.AuthFlowRepositoryPort;
import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;
import com.fivucsas.identity.repository.AuthFlowRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class AuthFlowRepositoryAdapter implements AuthFlowRepositoryPort {

    private final AuthFlowRepository jpaRepository;

    @Override
    public List<AuthFlow> findAllByTenantId(UUID tenantId) {
        return jpaRepository.findAllByTenantId(tenantId);
    }

    @Override
    public List<AuthFlow> findAllByTenantIdAndOperationType(UUID tenantId, OperationType operationType) {
        return jpaRepository.findAllByTenantIdAndOperationType(tenantId, operationType);
    }

    @Override
    public Optional<AuthFlow> findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(UUID tenantId, OperationType operationType) {
        return jpaRepository.findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(tenantId, operationType);
    }

    @Override
    public Optional<AuthFlow> findByIdAndTenantId(UUID id, UUID tenantId) {
        return jpaRepository.findByIdAndTenantId(id, tenantId);
    }

    @Override
    public Optional<AuthFlow> findById(UUID id) {
        return jpaRepository.findById(id);
    }

    @Override
    public AuthFlow save(AuthFlow flow) {
        return jpaRepository.save(flow);
    }

    @Override
    public void delete(AuthFlow flow) {
        jpaRepository.delete(flow);
    }
}
