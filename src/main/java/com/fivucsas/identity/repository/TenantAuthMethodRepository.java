package com.fivucsas.identity.repository;

import com.fivucsas.identity.domain.model.auth.AuthMethodType;
import com.fivucsas.identity.entity.TenantAuthMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TenantAuthMethodRepository extends JpaRepository<TenantAuthMethod, UUID> {
    List<TenantAuthMethod> findAllByTenantId(UUID tenantId);
    List<TenantAuthMethod> findAllByTenantIdAndIsEnabledTrue(UUID tenantId);
    Optional<TenantAuthMethod> findByTenantIdAndAuthMethodId(UUID tenantId, UUID authMethodId);

    /**
     * Looks up the per-(tenant, method-type) configuration row by the method's
     * enum type rather than its surrogate {@code auth_method_id}. Used by the
     * login-time enforcement gate which knows only the {@link AuthMethodType}.
     */
    Optional<TenantAuthMethod> findByTenantIdAndAuthMethod_Type(UUID tenantId, AuthMethodType type);
}
