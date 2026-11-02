-- ============================================================================
-- TEST-ONLY MIGRATION (loaded only by the Testcontainers integration profile via
-- spring.flyway.locations=classpath:db/migration,classpath:db/test-fixtures).
-- NOT on the production classpath; it never runs in prod.
-- ============================================================================
--
-- WHY THIS EXISTS (date time bomb, found 2026-11-02)
-- --------------------------------------------------
-- V40__partition_audit_logs.sql pre-creates monthly partitions only for
-- 2026-01 .. 2026-06 and relocates every legacy audit_logs row dated
-- >= 2026-01-01 into them. V15 seeds sample audit rows at
-- CURRENT_TIMESTAMP - N days, so on a fresh database migrated after
-- 2026-06-30 those rows fall outside every partition and V40 fails with
--     ERROR: no partition of relation "audit_logs" found for row
-- which aborts the Spring context of every integration test.
--
-- Prod is unaffected: it skipped V40 via a BASELINE marker (see V39_5), so
-- editing V40 would only risk a prod checksum mismatch for no prod benefit.
-- Instead, pin the V15 sample rows into V40's last pre-created month before
-- V40 runs. The rows are synthetic seed data; their exact age is irrelevant
-- to any test.
-- ============================================================================

UPDATE audit_logs
   SET created_at = TIMESTAMP '2026-06-15 12:00:00'
 WHERE created_at >= TIMESTAMP '2026-07-01';
