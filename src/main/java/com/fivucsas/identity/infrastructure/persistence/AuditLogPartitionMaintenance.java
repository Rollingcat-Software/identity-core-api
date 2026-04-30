package com.fivucsas.identity.infrastructure.persistence;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;

/**
 * Runtime safety net for {@code audit_logs} partitions.
 *
 * <p><b>Why this exists:</b> {@code audit_logs} is partitioned by
 * {@code RANGE (created_at)} (V40). Static migrations (V40, V52, ...)
 * pre-create monthly partitions, but if a migration is forgotten the next
 * time the runway runs out, the very first audit INSERT past the last
 * partition fails with:
 * <pre>no partition of relation "audit_logs" found for row</pre>
 * which then breaks every login, MFA step, OAuth grant, etc.
 *
 * <p><b>What it does:</b>
 * <ol>
 *   <li>On boot ({@code @PostConstruct}) it ensures the partitions for the
 *       <em>current</em> month and the <em>next two</em> months exist —
 *       creating them via the V41 helper {@code ensure_audit_logs_partition(date)}
 *       if missing.</li>
 *   <li>Once a month at 01:00 on the 1st ({@code @Scheduled}) it repeats
 *       the same check so a long-running pod doesn't drift past the runway
 *       just because nobody redeploys.</li>
 * </ol>
 *
 * <p><b>Idempotency:</b> {@code ensure_audit_logs_partition()} returns
 * {@code false} when the partition already exists and {@code true} only
 * when it actually creates one. We log {@code INFO} on creation and
 * {@code DEBUG} on no-op so ops sees the rare creation events.
 *
 * <p><b>Multi-replica caveat (ShedLock punted):</b> ShedLock is not on the
 * classpath. With multiple replicas, both {@code @PostConstruct} and the
 * monthly {@code @Scheduled} can fire concurrently. That is safe here
 * because the underlying SQL uses
 * {@code IF NOT EXISTS}-equivalent semantics inside
 * {@code ensure_audit_logs_partition()} (it checks {@code pg_class} before
 * issuing {@code CREATE TABLE}) and the wrapping {@code CREATE TABLE} is
 * itself a transactional DDL that one replica wins atomically. The other
 * replica's check sees the partition and short-circuits. Worst case is a
 * harmless duplicate {@code CREATE TABLE} that fails with
 * {@code 42P07 duplicate_table} — caught and logged here, not rethrown,
 * so a race never crashes the pod's boot.
 *
 * <p><b>Feature flag:</b> {@code audit-log.partition.auto-create} (default
 * true). Set to {@code false} to disable both the boot-time check and the
 * monthly schedule (useful for tests or when an external scheduler owns
 * partition creation).
 */
@Component
@ConditionalOnProperty(
        name = "audit-log.partition.auto-create",
        havingValue = "true",
        matchIfMissing = true)
@Slf4j
public class AuditLogPartitionMaintenance {

    /**
     * Look-ahead horizon: ensure the current month + this many additional
     * months are pre-created. Two months gives a comfortable buffer between
     * monthly scheduler runs and the next missing partition.
     */
    static final int LOOK_AHEAD_MONTHS = 2;

    private static final DateTimeFormatter PARTITION_LOG_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM");

    private final JdbcTemplate jdbc;

    public AuditLogPartitionMaintenance(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Boot-time guarantee: at least the current and next {@value #LOOK_AHEAD_MONTHS}
     * months have partitions before the application starts accepting traffic.
     */
    @PostConstruct
    void ensurePartitionsOnStartup() {
        log.info("[AuditLogPartitionMaintenance] Boot-time partition check starting "
                + "(look-ahead = {} months past current month)", LOOK_AHEAD_MONTHS);
        int created = ensureLookAhead();
        if (created == 0) {
            log.info("[AuditLogPartitionMaintenance] All look-ahead partitions already exist; no-op.");
        } else {
            log.info("[AuditLogPartitionMaintenance] Boot-time created {} new partition(s).", created);
        }
    }

    /**
     * Monthly safety net: 01:00 on the 1st of every month.
     * Keeps the look-ahead window populated even on long-running pods that
     * don't get redeployed across migration windows.
     *
     * <p>Cron format (Spring): {@code second minute hour day-of-month month day-of-week}.
     */
    @Scheduled(cron = "0 0 1 1 * *")
    void ensurePartitionsScheduled() {
        log.info("[AuditLogPartitionMaintenance] Monthly partition check firing.");
        int created = ensureLookAhead();
        if (created == 0) {
            log.info("[AuditLogPartitionMaintenance] Monthly check: all look-ahead partitions already exist.");
        } else {
            log.warn("[AuditLogPartitionMaintenance] Monthly check created {} partition(s) — "
                    + "static migrations have run out of runway; queue a V__audit_logs_partition_extend "
                    + "migration to re-establish multi-month buffer.", created);
        }
    }

    /**
     * Calls {@code ensure_audit_logs_partition(date)} for each month in the
     * look-ahead window. Returns the number of partitions actually created
     * (helper returns boolean true on creation).
     */
    int ensureLookAhead() {
        int created = 0;
        YearMonth start = YearMonth.now();
        for (int i = 0; i <= LOOK_AHEAD_MONTHS; i++) {
            YearMonth month = start.plusMonths(i);
            if (ensureMonth(month)) {
                created++;
            }
        }
        return created;
    }

    /**
     * Ensures a single month's partition exists. Returns true iff the helper
     * reports it actually created the partition. Failures (including the
     * narrow race window where two replicas both try to create the same
     * partition) are caught, logged and swallowed — partition creation is
     * advisory at runtime; the static migration is the source of truth.
     */
    boolean ensureMonth(YearMonth month) {
        LocalDate firstOfMonth = month.atDay(1);
        try {
            Boolean created = jdbc.queryForObject(
                    "SELECT ensure_audit_logs_partition(?)",
                    Boolean.class,
                    firstOfMonth);
            if (Boolean.TRUE.equals(created)) {
                log.info("[AuditLogPartitionMaintenance] Created audit_logs partition for {}.",
                        month.format(PARTITION_LOG_FMT));
                return true;
            }
            log.debug("[AuditLogPartitionMaintenance] Partition for {} already exists; skipped.",
                    month.format(PARTITION_LOG_FMT));
            return false;
        } catch (Exception e) {
            // Possible causes:
            //   - duplicate_table (42P07) from a multi-replica race — benign.
            //   - DB unreachable — already logged at framework level.
            //   - V41 helper missing — surface the error so deployment is fixed.
            log.warn("[AuditLogPartitionMaintenance] ensure_audit_logs_partition({}) failed: {}",
                    firstOfMonth, e.getMessage());
            return false;
        }
    }
}
