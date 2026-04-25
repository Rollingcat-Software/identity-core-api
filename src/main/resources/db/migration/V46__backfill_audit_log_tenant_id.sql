-- V46: Backfill audit_logs.tenant_id from users.tenant_id
-- ---------------------------------------------------------------------------
-- Symptom (prod, 2026-04-25):
--   SELECT count(*) FROM audit_logs
--    WHERE tenant_id IS NULL AND user_id IS NOT NULL;
--   -> 943   (out of 949 total rows)
--
-- Tenant-admin's GET /api/v1/audit-logs filters by tenant_id, so 943 rows
-- describing tenant activity were invisible to every tenant admin. Marmara
-- admins only saw the 6 V15 seed rows.
--
-- Root cause: AuditLogAdapter.saveAuditLog never set tenant_id when building
-- the AuditLog entity. Fixed in the same PR — every new row written from now
-- on resolves tenant_id from users.tenant_id at write time. This migration
-- repairs the historical rows.
--
-- Strategy:
--   UPDATE audit_logs.tenant_id <- users.tenant_id
--   WHERE audit_logs.user_id = users.id
--     AND audit_logs.tenant_id IS NULL
--     AND users.tenant_id IS NOT NULL
--
-- Notes:
--   * audit_logs is range-partitioned by created_at (V40). UPDATE on the
--     partitioned root cascades to every partition automatically; we do not
--     need to enumerate audit_logs_2026_01..audit_logs_2026_06 or
--     audit_logs_legacy individually.
--   * RLS policies from V25/V40 are bypassed by Flyway because it runs as
--     the table owner.
--   * Idempotent: re-running this migration is a no-op once tenant_id is
--     populated, because the WHERE clause filters out non-NULL rows.
--   * Soft-deleted users still have tenant_id; we only skip rows whose user
--     was hard-deleted (FK-cascade) or whose tenant_id was somehow NULL.
--   * Rows with user_id IS NULL stay NULL — they are anonymous failed-login
--     attempts or system-level events, intentionally cross-tenant.
-- ---------------------------------------------------------------------------

BEGIN;

-- Backfill from users.tenant_id where we have a user reference.
UPDATE audit_logs AS al
SET    tenant_id = u.tenant_id
FROM   users u
WHERE  al.user_id = u.id
  AND  al.tenant_id IS NULL
  AND  u.tenant_id IS NOT NULL;

-- Sanity log: how many user-scoped rows still have NULL tenant_id?
-- These are typically failed-login attempts (user_id IS NULL) or rows whose
-- referenced user no longer exists. Both are acceptable; we just record the
-- count for the audit trail.
DO $$
DECLARE
    remaining_null_with_user bigint;
    total_user_scoped        bigint;
BEGIN
    SELECT count(*) INTO remaining_null_with_user
      FROM audit_logs
     WHERE tenant_id IS NULL
       AND user_id IS NOT NULL;

    SELECT count(*) INTO total_user_scoped
      FROM audit_logs
     WHERE user_id IS NOT NULL;

    RAISE NOTICE 'V46 backfill complete. user-scoped rows still NULL: % / %',
                 remaining_null_with_user, total_user_scoped;
END $$;

COMMIT;
