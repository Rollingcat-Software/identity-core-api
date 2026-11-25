package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.AuthorTrialPlanEntryEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

/** Spring Data repository for the trial round plan (V90). */
public interface AuthorTrialPlanEntryRepository extends JpaRepository<AuthorTrialPlanEntryEntity, UUID> {

    /**
     * Locks and returns the first free slot for the key. {@code SKIP LOCKED} lets
     * two concurrent trial tabs claim different slots instead of blocking; the
     * caller must run inside a transaction so the row lock survives until the
     * attempt row is created and the slot is assigned.
     */
    @Query(value = """
            SELECT * FROM author_trial_plan_entries
             WHERE tenant_id = :tenantId
               AND participant_code = :participantCode
               AND mode = :mode
               AND attempt_id IS NULL
             ORDER BY round_no ASC, position ASC
             LIMIT 1
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    Optional<AuthorTrialPlanEntryEntity> lockNextFreeSlot(
            @Param("tenantId") UUID tenantId,
            @Param("participantCode") String participantCode,
            @Param("mode") String mode);

    @Query("""
            SELECT COALESCE(MAX(e.roundNo), 0)
              FROM AuthorTrialPlanEntryEntity e
             WHERE e.tenantId = :tenantId
               AND e.participantCode = :participantCode
               AND e.mode = :mode
            """)
    int maxRound(@Param("tenantId") UUID tenantId,
                 @Param("participantCode") String participantCode,
                 @Param("mode") String mode);

    long deleteByTenantId(UUID tenantId);
}