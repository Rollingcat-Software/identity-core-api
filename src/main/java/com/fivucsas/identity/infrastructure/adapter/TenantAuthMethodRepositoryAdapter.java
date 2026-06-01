package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.TenantAuthMethodRepositoryPort;
import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.TenantAuthMethod;
import com.fivucsas.identity.repository.TenantAuthMethodRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class TenantAuthMethodRepositoryAdapter implements TenantAuthMethodRepositoryPort {

    private final TenantAuthMethodRepository jpaRepository;

    @Override
    public List<TenantAuthMethod> findAllByTenantId(UUID tenantId) {
        return jpaRepository.findAllByTenantId(tenantId);
    }

    @Override
    public Optional<TenantAuthMethod> findByTenantIdAndAuthMethodId(UUID tenantId, UUID authMethodId) {
        return jpaRepository.findByTenantIdAndAuthMethodId(tenantId, authMethodId);
    }

    @Override
    public Optional<TenantAuthMethod> findByTenantIdAndType(UUID tenantId, AuthMethodType type) {
        return jpaRepository.findByTenantIdAndAuthMethod_Type(tenantId, type);
    }

    @Override
    public TenantAuthMethod save(TenantAuthMethod tenantAuthMethod) {
        return jpaRepository.save(tenantAuthMethod);
    }
}
