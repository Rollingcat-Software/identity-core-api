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

    /**
     * Persists and immediately flushes to the database. Needed when a later write
     * in the same transaction would otherwise collide with the partial unique
     * index {@code uq_auth_flow_default(tenant_id, operation_type)}: the previous
     * default must be cleared in the DB <em>before</em> a new flow claims it,
     * because the index is checked per-statement (not deferred to commit).
     */
    AuthFlow saveAndFlush(AuthFlow flow);

    void delete(AuthFlow flow);
}
