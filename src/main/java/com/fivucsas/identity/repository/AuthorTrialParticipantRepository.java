package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuthorTrialParticipantEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Spring Data repository for the trial participant map (V90). */
public interface AuthorTrialParticipantRepository extends JpaRepository<AuthorTrialParticipantEntity, UUID> {

    List<AuthorTrialParticipantEntity> findByTenantIdOrderByParticipantCodeAsc(UUID tenantId);

    Optional<AuthorTrialParticipantEntity> findByTenantIdAndParticipantCode(UUID tenantId, String participantCode);

    long deleteByTenantId(UUID tenantId);
}