package com.fivucsas.identity.repository;

import com.fivucsas.identity.domain.model.auth.OperationType;
import com.fivucsas.identity.entity.AuthFlow;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthFlowRepository extends JpaRepository<AuthFlow, UUID> {
    List<AuthFlow> findAllByTenantId(UUID tenantId);
    List<AuthFlow> findAllByTenantIdAndOperationType(UUID tenantId, OperationType operationType);
    Optional<AuthFlow> findByTenantIdAndIsDefaultTrueAndIsActiveTrueAndOperationType(UUID tenantId, OperationType operationType);
    Optional<AuthFlow> findByIdAndTenantId(UUID id, UUID tenantId);
}
