-- V51: Extend audit_logs monthly partitions through 2027-12.
-- ---------------------------------------------------------------------------
-- Background:
--   V40 partitioned audit_logs by RANGE (created_at) and pre-created
--   2026-01..2026-06. The highest partition created by V40 covers
--   FROM '2026-06-01' TO '2026-07-01' (i.e. data for June 2026).
--   V41 added an idempotent helper ensure_audit_logs_partition(date) but it
--   was never wired to a scheduler.
--
-- Symptom if not applied:
--   First INSERT into audit_logs with created_at >= 2026-07-01 raises
--   "no partition of relation audit_logs found for row" — every audit
--   write (login, MFA step, OAuth grant, etc.) fails.
--
-- Fix:
--   Idempotently create monthly partitions for 2026-07..2027-12 (18 months
--   runway). Naming and bound shape exactly match V40 so the existing
--   ensure_audit_logs_partition() helper continues to work.
--
-- Companion runtime safeguard:
--   AuditLogPartitionMaintenance @PostConstruct (and @Scheduled monthly)
--   calls ensure_audit_logs_partition() to keep at least 2 months of
--   look-ahead even if this static migration is forgotten the next time
--   the runway runs out.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_logs_2026_07 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS audit_logs_2026_08 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS audit_logs_2026_09 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS audit_logs_2026_10 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE IF NOT EXISTS audit_logs_2026_11 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS audit_logs_2026_12 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_04 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-04-01') TO ('2027-05-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_05 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-05-01') TO ('2027-06-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_06 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-06-01') TO ('2027-07-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_07 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-07-01') TO ('2027-08-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_08 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-08-01') TO ('2027-09-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_09 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-09-01') TO ('2027-10-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_10 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-10-01') TO ('2027-11-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_11 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-11-01') TO ('2027-12-01');
CREATE TABLE IF NOT EXISTS audit_logs_2027_12 PARTITION OF audit_logs
    FOR VALUES FROM ('2027-12-01') TO ('2028-01-01');

-- Verify in prod after apply:
--   SELECT child.relname, pg_get_expr(child.relpartbound, child.oid)
--     FROM pg_inherits i
--     JOIN pg_class parent ON parent.oid = i.inhparent
--     JOIN pg_class child  ON child.oid  = i.inhrelid
--    WHERE parent.relname = 'audit_logs'
--    ORDER BY child.relname;
