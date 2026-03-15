package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for AuthFlow persistence operations.
 */
public interface AuthFlowRepositoryPort {

    List<AuthFlow> findAllByTenantId(UUID tenantId);

    List<AuthFlow> findAllByTenantIdAndOperationType(UUID tenantId, OperationType operationType);

    Optional<AuthFlow> findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(UUID tenantId, OperationType operationType);

    Optional<AuthFlow> findByIdAndTenantId(UUID id, UUID tenantId);

    Optional<AuthFlow> findById(UUID id);

    AuthFlow save(AuthFlow flow);

    void delete(AuthFlow flow);
}
