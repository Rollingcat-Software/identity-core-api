package com.fivucsas.identity.application.port.output;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Output port for the durable biometric-template deletion outbox
 * ({@code biometric_deletion_outbox}, V87).
 *
 * <p>When a user is deleted, their face + voice templates live in a separate
 * service (biometric-processor). The deletion intent is recorded here in the
 * SAME transaction as the user soft delete / hard purge, then drained
 * asynchronously by {@code BiometricDeletionOutboxWorker}. This makes the
 * erasure durable across bio outages and restarts.
 */
public interface BiometricDeletionOutboxPort {

    /** Biometric methods whose templates are held by biometric-processor. */
    enum Method { FACE, VOICE }

    /** A pending outbox row, decoupled from the JPA entity. */
    record PendingDeletion(UUID id, UUID userId, UUID tenantId, Method method, int attempts) {}

    /**
     * Idempotently records the intent to delete {@code method} templates for
     * {@code userId}. A second enqueue for the same (user, method) is a no-op
     * (unique constraint + ON CONFLICT DO NOTHING). The user's tenant is
     * resolved by the adapter (informational only).
     *
     * @return true if a new row was inserted, false if one already existed
     */
    boolean enqueue(UUID userId, Method method);

    /** Pending rows that are due ({@code next_attempt_at} null or &lt;= now) with attempts below the cap. */
    List<PendingDeletion> findDue(Instant now, int maxAttempts, int limit);

    /** Marks a row done (bio deleted, or nothing was enrolled). */
    void markCompleted(UUID id, Instant completedAt);

    /** Records a failed attempt: increments attempts, stores the error, schedules the retry. */
    void markFailed(UUID id, String lastError, Instant nextAttemptAt);
}
