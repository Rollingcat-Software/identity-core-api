package com.fivucsas.identity.repository;

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
}
