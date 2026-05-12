-- V61: Lock down audit_logs.tenant_id with NOT NULL
-- ---------------------------------------------------------------------------
-- Context:
--   * V46 (2026-04-25) ran a first-wave backfill for user-scoped NULLs.
--   * V59 (2026-05-11) ran a defensive re-run of V46 PLUS stamped any truly
--     anonymous-event rows with the well-known sentinel UUID
--     00000000-0000-0000-0000-000000000000. The code-side fix that lands the
--     sentinel directly from the AuditLogAdapter went out in the same PR.
--   * After V59, prod was at 0 NULL rows / 1168 total (verified
--     2026-05-11 in Session notes).
--
-- V59 deliberately did NOT add the NOT NULL constraint. The plan there was to
-- soak for a week so any straggler writer that still emitted NULL would be
-- caught in a metric (audit.publish.failure with NotNullViolation) rather
-- than a 500. That window has now elapsed without sightings, so V61 closes
-- the gate.
--
-- Strategy:
--   1. Re-verify the NULL count is zero immediately before the ALTER. If a
--      straggler writer slipped a NULL in between V59 (2026-05-11) and V61
--      application, the migration FAILS LOUDLY here. That is the correct
--      behaviour — we'd rather have Flyway block the deploy than silently
--      mutate prod data inside a constraint migration. Operator can then:
--        a) re-run V59 by hand on the deviant rows, or
--        b) UPDATE audit_logs SET tenant_id='00000000-...' WHERE tenant_id IS NULL,
--      whichever is appropriate after diagnosing the source writer.
--   2. ALTER COLUMN ... SET NOT NULL. This is a metadata-only change on
--      PostgreSQL 12+ when the column already has zero NULLs (no full table
--      rewrite). audit_logs is large but the scan to validate the constraint
--      is fast given the existing btree indexes on (tenant_id, created_at).
--   3. Do NOT set a column DEFAULT. Sentinel writes are the writer's
--      responsibility (AuditLogAdapter). A DEFAULT here would hide writer
--      bugs by silently substituting the sentinel instead of failing fast
--      on NotNullViolation.
--
-- Idempotency:
--   ALTER ... SET NOT NULL is idempotent at the catalog level — applying it
--   to a column that is already NOT NULL is a no-op on Postgres.
--
-- Rollback:
--   ALTER TABLE audit_logs ALTER COLUMN tenant_id DROP NOT NULL;
--   (No data loss; just relaxes the constraint.)
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    null_count BIGINT;
BEGIN
    SELECT count(*) INTO null_count
      FROM audit_logs
     WHERE tenant_id IS NULL;

    IF null_count > 0 THEN
        RAISE EXCEPTION
          'audit_logs.tenant_id has % NULL row(s); V59 backfill (sentinel %) must run cleanly before V61. Re-run V59 manually on the deviant rows then re-apply V61.',
          null_count, '00000000-0000-0000-0000-000000000000';
    END IF;

    RAISE NOTICE 'V61 pre-check OK: audit_logs.tenant_id NULL count = 0';
END $$;

ALTER TABLE audit_logs ALTER COLUMN tenant_id SET NOT NULL;

DO $$
BEGIN
    RAISE NOTICE 'V61 applied: audit_logs.tenant_id is now NOT NULL';
END $$;
