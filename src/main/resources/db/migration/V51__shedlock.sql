-- ShedLock storage table — exclusive lease for @Scheduled jobs.
--
-- net.javacrumbs.shedlock acquires a row-level lock here before each
-- scheduled tick so multiple replicas of identity-core-api do not all
-- run the same cron simultaneously. Schema is mandated by the
-- shedlock-provider-jdbc-template adapter; do not change column names
-- or types.
--
-- See SoftDeletePurgeJob.runScheduled — first @SchedulerLock-annotated
-- job in the project. Future scheduled jobs should reuse this table.
--
-- Numbering note: this is V51 (renumbered from V53 to keep the
-- migration chain contiguous after V50). The feat/v51-forbid-hard-delete-p1-7
-- branch carries a separate "V51 BEFORE DELETE trigger" migration that
-- never reached main; when that branch merges it must renumber to V52
-- or later and add a SET LOCAL app.allow_hard_delete='on' bypass
-- inside SoftDeletePurgeJob.purgeBatch.

CREATE TABLE IF NOT EXISTS shedlock (
    name       VARCHAR(64)    NOT NULL,
    lock_until TIMESTAMP      NOT NULL,
    locked_at  TIMESTAMP      NOT NULL,
    locked_by  VARCHAR(255)   NOT NULL,
    PRIMARY KEY (name)
);
