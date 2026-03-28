package com.fivucsas.identity.repository;

import com.fivucsas.identity.domain.model.auth.VerificationSessionStatus;
import com.fivucsas.identity.entity.VerificationSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface VerificationSessionRepository extends JpaRepository<VerificationSession, UUID> {

    List<VerificationSession> findAllByUserIdOrderByCreatedAtDesc(UUID userId);

    List<VerificationSession> findAllByUserIdAndStatus(UUID userId, VerificationSessionStatus status);

    List<VerificationSession> findAllByTenantIdOrderByCreatedAtDesc(UUID tenantId);

    Optional<VerificationSession> findByIdAndTenantId(UUID id, UUID tenantId);
}
