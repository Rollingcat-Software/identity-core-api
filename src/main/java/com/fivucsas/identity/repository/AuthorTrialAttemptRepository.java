package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuthorTrialAttemptEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Spring Data repository for the trial attempt log (V90). */
public interface AuthorTrialAttemptRepository extends JpaRepository<AuthorTrialAttemptEntity, UUID> {

    Optional<AuthorTrialAttemptEntity> findByMfaSessionId(UUID mfaSessionId);

    Optional<AuthorTrialAttemptEntity> findByPuzzleSessionId(String puzzleSessionId);

    List<AuthorTrialAttemptEntity> findByTenantIdOrderByStartedAtAsc(UUID tenantId, Pageable pageable);

    long deleteByTenantId(UUID tenantId);
}