package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.VerificationStepResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface VerificationStepResultRepository extends JpaRepository<VerificationStepResult, UUID> {

    List<VerificationStepResult> findAllBySessionIdOrderByStepNumberAsc(UUID sessionId);

    Optional<VerificationStepResult> findBySessionIdAndStepNumber(UUID sessionId, int stepNumber);

    /**
     * Batch-fetch step results for a set of session ids in a single query.
     * Avoids the N+1 pattern when computing failure-reason aggregations over
     * many failed sessions (Copilot post-merge round 5).
     */
    List<VerificationStepResult> findAllBySessionIdInOrderBySessionIdAscStepNumberAsc(
            Collection<UUID> sessionIds);
}
