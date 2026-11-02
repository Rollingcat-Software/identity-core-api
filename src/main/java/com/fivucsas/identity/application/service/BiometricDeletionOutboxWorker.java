package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort;
import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort.Method;
import com.fivucsas.identity.application.port.output.BiometricDeletionOutboxPort.PendingDeletion;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Drains {@code biometric_deletion_outbox} (V87): for every pending (user, method)
 * row it asks biometric-processor to delete the user's FACE / VOICE templates via
 * {@link BiometricServicePort}.
 *
 * <p>Outcome per row:
 * <ul>
 *   <li>bio {@code success=true} → completed.</li>
 *   <li>bio 404 / nothing enrolled ({@code notEnrolled=true}, set by the adapter) →
 *       completed: the goal state (no template) already holds.</li>
 *   <li>anything else (error map, exception, null) → attempt recorded with
 *       {@code last_error}, retried after an exponential backoff
 *       ({@code base * 2^attempts}, capped). After {@code max-attempts} the row
 *       stays pending-but-parked (worker no longer selects it) and is logged at
 *       ERROR for an operator.</li>
 * </ul>
 *
 * <p>Idempotent: bio deletes are idempotent, the completed/failed updates are
 * guarded by {@code completed_at IS NULL}, and ShedLock keeps a single instance
 * draining at a time.
 *
 * <p>Kill-switch: {@code app.biometric-deletion.outbox.enabled}
 * ({@code APP_BIOMETRIC_DELETION_OUTBOX_ENABLED}, default true). When false rows
 * keep accumulating (the durable intent is never lost) and drain once re-enabled.
 */
@Service
@Slf4j
public class BiometricDeletionOutboxWorker {

    private final BiometricDeletionOutboxPort outbox;
    private final BiometricServicePort biometricService;
    private final Clock clock;

    @Value("${app.biometric-deletion.outbox.enabled:true}")
    private boolean enabled = true;

    @Value("${app.biometric-deletion.outbox.max-attempts:10}")
    private int maxAttempts = 10;

    @Value("${app.biometric-deletion.outbox.batch-size:50}")
    private int batchSize = 50;

    @Value("${app.biometric-deletion.outbox.base-backoff-seconds:60}")
    private long baseBackoffSeconds = 60;

    @Value("${app.biometric-deletion.outbox.max-backoff-seconds:21600}")
    private long maxBackoffSeconds = 21_600; // 6h

    @Autowired
    public BiometricDeletionOutboxWorker(BiometricDeletionOutboxPort outbox,
                                         BiometricServicePort biometricService) {
        this(outbox, biometricService, Clock.systemUTC());
    }

    BiometricDeletionOutboxWorker(BiometricDeletionOutboxPort outbox,
                                  BiometricServicePort biometricService,
                                  Clock clock) {
        this.outbox = outbox;
        this.biometricService = biometricService;
        this.clock = clock;
    }

    @Scheduled(
            initialDelayString = "${app.biometric-deletion.outbox.initial-delay-ms:60000}",
            fixedDelayString = "${app.biometric-deletion.outbox.poll-interval-ms:60000}")
    @SchedulerLock(name = "BiometricDeletionOutboxWorker_drain",
            lockAtMostFor = "PT10M", lockAtLeastFor = "PT5S")
    public void runScheduled() {
        if (!enabled) {
            log.debug("Biometric deletion outbox drain skipped — app.biometric-deletion.outbox.enabled=false");
            return;
        }
        int done = drainOnce();
        if (done > 0) {
            log.info("Biometric deletion outbox drained: {} row(s) completed", done);
        }
    }

    /**
     * Processes one batch of due rows. Each row is handled independently (one
     * failure never blocks the rest).
     *
     * @return number of rows completed in this pass
     */
    public int drainOnce() {
        Instant now = clock.instant();
        List<PendingDeletion> due = outbox.findDue(now, maxAttempts, batchSize);
        int completed = 0;
        for (PendingDeletion row : due) {
            if (process(row)) {
                completed++;
            }
        }
        return completed;
    }

    private boolean process(PendingDeletion row) {
        String error;
        try {
            Map<String, Object> result = row.method() == Method.FACE
                    ? biometricService.deleteFace(row.userId())
                    : biometricService.deleteVoice(row.userId());
            if (isDeleted(result)) {
                outbox.markCompleted(row.id(), clock.instant());
                log.info("Biometric {} templates deleted for user {} (outbox {})",
                        row.method(), row.userId(), row.id());
                return true;
            }
            error = result == null ? "null response from biometric service"
                    : String.valueOf(result.getOrDefault("message", result));
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        }

        int attemptNo = row.attempts() + 1;
        Instant next = clock.instant().plus(backoff(row.attempts()));
        outbox.markFailed(row.id(), error, next);
        if (attemptNo >= maxAttempts) {
            log.error("Biometric {} deletion for user {} gave up after {} attempts (outbox {}): {} — "
                    + "operator action required (reset attempts to retry)",
                    row.method(), row.userId(), attemptNo, row.id(), error);
        } else {
            log.warn("Biometric {} deletion for user {} failed (attempt {}/{}), retry at {}: {}",
                    row.method(), row.userId(), attemptNo, maxAttempts, next, error);
        }
        return false;
    }

    /** {@code base * 2^priorAttempts}, capped at {@code maxBackoffSeconds}. */
    Duration backoff(int priorAttempts) {
        int shift = Math.min(Math.max(priorAttempts, 0), 30);
        long seconds = baseBackoffSeconds * (1L << shift);
        if (seconds <= 0 || seconds > maxBackoffSeconds) {
            seconds = maxBackoffSeconds;
        }
        return Duration.ofSeconds(seconds);
    }

    static boolean isDeleted(Map<String, Object> result) {
        if (result == null) {
            return false;
        }
        return isTrue(result.get("success")) || isTrue(result.get("notEnrolled"));
    }

    private static boolean isTrue(Object v) {
        return Boolean.TRUE.equals(v) || "true".equalsIgnoreCase(String.valueOf(v));
    }
}
