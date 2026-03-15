package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.TenantAuthMethod;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for TenantAuthMethod persistence operations.
 */
public interface TenantAuthMethodRepositoryPort {

    List<TenantAuthMethod> findAllByTenantId(UUID tenantId);

    Optional<TenantAuthMethod> findByTenantIdAndAuthMethodId(UUID tenantId, UUID authMethodId);

    TenantAuthMethod save(TenantAuthMethod tenantAuthMethod);
}
