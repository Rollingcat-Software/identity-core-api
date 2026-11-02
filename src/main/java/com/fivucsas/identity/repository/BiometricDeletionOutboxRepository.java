package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.BiometricDeletionOutboxEntry;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface BiometricDeletionOutboxRepository extends JpaRepository<BiometricDeletionOutboxEntry, UUID> {

    /**
     * Idempotent enqueue. The tenant is read straight from {@code users} with a
     * native sub-select so it bypasses the Hibernate tenantFilter and the
     * soft-delete {@code @SQLRestriction} (the row may already be soft-deleted
     * in this transaction). Joins the caller's transaction when one is active.
     */
    @Modifying
    @Transactional
    @Query(value = "INSERT INTO biometric_deletion_outbox "
            + "(id, user_id, tenant_id, method, created_at, attempts) "
            + "VALUES (:id, :userId, (SELECT u.tenant_id FROM users u WHERE u.id = :userId), "
            + ":method, CURRENT_TIMESTAMP, 0) "
            + "ON CONFLICT (user_id, method) DO NOTHING",
            nativeQuery = true)
    int insertIfAbsent(@Param("id") UUID id,
                       @Param("userId") UUID userId,
                       @Param("method") String method);

    @Query("SELECT e FROM BiometricDeletionOutboxEntry e "
            + "WHERE e.completedAt IS NULL AND e.attempts < :maxAttempts "
            + "AND (e.nextAttemptAt IS NULL OR e.nextAttemptAt <= :now) "
            + "ORDER BY e.createdAt ASC")
    List<BiometricDeletionOutboxEntry> findDue(@Param("now") Instant now,
                                               @Param("maxAttempts") int maxAttempts,
                                               Pageable pageable);

    @Modifying
    @Transactional
    @Query("UPDATE BiometricDeletionOutboxEntry e SET e.completedAt = :completedAt, "
            + "e.attempts = e.attempts + 1, e.lastError = NULL, e.nextAttemptAt = NULL "
            + "WHERE e.id = :id AND e.completedAt IS NULL")
    int markCompleted(@Param("id") UUID id, @Param("completedAt") Instant completedAt);

    @Modifying
    @Transactional
    @Query("UPDATE BiometricDeletionOutboxEntry e SET e.attempts = e.attempts + 1, "
            + "e.lastError = :lastError, e.nextAttemptAt = :nextAttemptAt "
            + "WHERE e.id = :id AND e.completedAt IS NULL")
    int markFailed(@Param("id") UUID id,
                   @Param("lastError") String lastError,
                   @Param("nextAttemptAt") Instant nextAttemptAt);
}
