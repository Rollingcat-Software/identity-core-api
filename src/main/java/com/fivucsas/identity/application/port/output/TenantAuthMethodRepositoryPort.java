package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
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

    /**
     * Looks up the per-(tenant, method-type) row by the method's enum type.
     * Used by the login-time enforcement gate.
     */
    Optional<TenantAuthMethod> findByTenantIdAndType(UUID tenantId, AuthMethodType type);

    TenantAuthMethod save(TenantAuthMethod tenantAuthMethod);
}
