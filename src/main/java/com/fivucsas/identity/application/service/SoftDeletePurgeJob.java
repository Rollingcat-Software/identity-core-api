package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Scheduled job that permanently deletes users soft-deleted more than 30 days ago
 * (GDPR Art. 17 / KVKK right-to-erasure).
 *
 * <p>Runs daily at 03:30 server time when {@code app.purge.softDelete.enabled=true}.
 * Default is false so the job is idle until an operator flips the flag after
 * validating behaviour via {@code DELETE /api/v1/admin/purge/dry-run}.</p>
 *
 * <p>Cascade strategy:
 * <ul>
 *   <li>Most user-related tables declare {@code ON DELETE CASCADE} (V11, V16, V18, V19,
 *       V22, V30, V6) so deleting the user removes enrollments, sessions, devices,
 *       WebAuthn credentials, API keys, NFC cards, MFA sessions and refresh tokens.</li>
 *   <li>{@code audit_logs.user_id} is {@code ON DELETE SET NULL} (V5) — audit history
 *       persists per regulatory requirement (SOC2 / ISO 27001 / KVKK 7-year
 *       retention), with the user reference nulled.</li>
 * </ul>
 *
 * <p>Safety:
 * <ul>
 *   <li>Feature-flagged ({@code app.purge.softDelete.enabled}, default false).</li>
 *   <li>Processes in batches of 100 to keep transactions short.</li>
 *   <li>Emits {@code USER_HARD_PURGED} audit event per user and a summary log line.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SoftDeletePurgeJob {

    /** 30-day retention window before a soft-deleted user is permanently purged. */
    public static final Duration RETENTION_WINDOW = Duration.ofDays(30);

    /** Batch size for iterative deletion — keeps individual transactions short. */
    private static final int BATCH_SIZE = 100;

    private final UserRepository userRepository;
    private final AuditLogPort auditLogPort;

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${app.purge.softDelete.enabled:false}")
    private boolean enabled;

    /**
     * Daily scheduled purge at 03:30 server time.
     * Skips entirely if the feature flag is false.
     */
    @Scheduled(cron = "0 30 3 * * *")
    @SchedulerLock(
            name = "SoftDeletePurgeJob_runScheduled",
            // Hold the lock at most 25 minutes so a stuck instance can't block
            // the next day's run. Hold it at least 1 minute so the lock outlasts
            // a JVM restart that completed the work but couldn't release.
            lockAtMostFor = "PT25M",
            lockAtLeastFor = "PT1M"
    )
    public void runScheduled() {
        if (!enabled) {
            log.debug("Soft-delete purge job skipped — app.purge.softDelete.enabled=false");
            return;
        }
        PurgeResult result = purge();
        log.info("Soft-delete purge complete: purged={}, cutoff={}", result.purged(), result.cutoff());
    }

    /**
     * Executes the purge synchronously and returns the result. Callable from admin
     * endpoints or the scheduler. Honours the feature flag — a disabled flag yields
     * a zero-purge {@code PurgeResult} (matches dry-run semantics when disabled).
     */
    public PurgeResult purge() {
        if (!enabled) {
            log.warn("purge() invoked with feature flag disabled — returning 0");
            return new PurgeResult(Instant.now().minus(RETENTION_WINDOW), 0, List.of());
        }
        Instant cutoff = Instant.now().minus(RETENTION_WINDOW);
        int purged = 0;
        List<UUID> purgedIds = new ArrayList<>();

        while (true) {
            Page<User> batch = userRepository.findPurgeCandidates(
                cutoff, PageRequest.of(0, BATCH_SIZE));
            if (batch.isEmpty()) {
                break;
            }
            int batchPurged = purgeBatch(batch.getContent(), purgedIds);
            purged += batchPurged;
            if (batchPurged < BATCH_SIZE) {
                break;   // fewer than batch-size means we've drained the set
            }
        }

        return new PurgeResult(cutoff, purged, purgedIds);
    }

    /**
     * Lists users that WOULD be purged by {@link #purge()} at the current instant.
     * Does not modify any rows and ignores the feature flag — useful for dry-run
     * verification before operators enable the job in production.
     */
    @Transactional(readOnly = true)
    public DryRunResult dryRun() {
        Instant cutoff = Instant.now().minus(RETENTION_WINDOW);
        // Cap the inspected set so an unexpectedly large backlog doesn't OOM the caller.
        Page<User> page = userRepository.findPurgeCandidates(cutoff, PageRequest.of(0, 1000));
        List<UUID> ids = page.getContent().stream().map(User::getId).toList();
        return new DryRunResult(cutoff, page.getTotalElements(), ids);
    }

    /**
     * Deletes a batch of users in a single transaction. The {@code REQUIRES_NEW}
     * propagation means a failure in one batch doesn't poison the whole purge run.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    protected int purgeBatch(List<User> users, List<UUID> purgedIdsOut) {
        // Bypass V53 forbid_hard_delete trigger for this legitimate GDPR Art. 17 / KVKK
        // hard-purge transaction. SET LOCAL is automatically reset at TX commit/rollback,
        // so the bypass cannot leak into other sessions or other TXs in this thread.
        // PostgreSQL SET does not accept parameters through prepared statements, so we
        // use a hard-coded literal — no user input ever flows here.
        entityManager.createNativeQuery("SET LOCAL app.allow_hard_delete = 'on'")
                .executeUpdate();

        int purged = 0;
        for (User user : users) {
            try {
                UUID userId = user.getId();
                String emailSnapshot = user.getEmail();  // snapshot before delete for audit
                userRepository.delete(user);
                userRepository.flush();   // force the FK cascades to run inside this tx
                auditLogPort.logSecurityEvent(
                    null,  // actor is the system scheduler, not a user
                    "USER_HARD_PURGED",
                    null,
                    String.format("userId=%s, email=%s, deletedAt=%s",
                        userId, emailSnapshot, user.getDeletedAt()));
                purgedIdsOut.add(userId);
                purged++;
            } catch (Exception e) {
                // Per-user failure — log and continue so one bad row doesn't block the whole
                // batch. The retention window is generous enough that we can retry tomorrow.
                log.error("Failed to purge user {}: {}", user.getId(), e.getMessage(), e);
            }
        }
        return purged;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Result of a completed purge run. */
    public record PurgeResult(Instant cutoff, int purged, List<UUID> purgedIds) {}

    /** Result of a dry-run inspection (no rows modified). */
    public record DryRunResult(Instant cutoff, long candidateCount, List<UUID> candidateIds) {}
}
