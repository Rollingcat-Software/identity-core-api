-- V59: Backfill audit_logs.tenant_id NULLs + introduce the "system" sentinel tenant
-- ---------------------------------------------------------------------------
-- Symptom (prod, SENIOR_DB_REVIEW_2026-05-04 §Appendix C):
--   SELECT count(*) FROM audit_logs WHERE tenant_id IS NULL;
--   -> 140 / 1107  (12.6% and drifting up)
--
-- Root cause: anonymous-endpoint emitters write audit rows before there is an
-- authenticated tenant in scope. The current write path (AuditLogAdapter)
-- resolves tenant_id from users.tenant_id only when a userId is supplied —
-- pre-auth events (failed login, /oauth2/token, /oauth2/authorize, PKCE
-- failure) have no userId, so tenant_id stays NULL. Tenant-admin's
-- GET /api/v1/audit-logs filters by tenant_id, so those rows are invisible to
-- every tenant admin AND uncountable in cross-tenant security dashboards.
--
-- V46 (2026-04-25) handled the first wave for *user-scoped* NULLs. This V59
-- closes the remaining anonymous-event NULLs by introducing a well-known
-- "system" sentinel tenant_id. The code-side fix (AuditLogAdapter +
-- AuditLogPort) lands in the same PR and writes the sentinel for new rows
-- where tenant is not resolvable.
--
-- Strategy:
--   1. Re-run V46's user-tenant backfill defensively. Any rows that landed
--      between V46 (2026-04-25) and now where the writer fell through to
--      NULL (transient DB error, deleted user) are repaired if their user
--      still exists.
--   2. Stamp the remaining NULLs with the sentinel UUID
--      00000000-0000-0000-0000-000000000000. We DO NOT seed a real tenant
--      row for this UUID — it is a logical marker, not a tenant entity.
--      The /api/v1/audit-logs admin endpoint can choose to filter sentinel
--      rows out (cross-tenant view) or expose them (root admin view).
--
-- Why not NOT NULL constraint?
--   Deliberately not added in this migration. We need the backfill to soak
--   in prod first so any straggler writer that still emits NULL is caught
--   in a metric (audit.publish.failure with NotNullViolation) rather than a
--   500. Adding the NOT NULL is a P2 follow-up (separate migration) after
--   a week of green metrics.
--
-- Idempotency:
--   * UPDATE … WHERE tenant_id IS NULL is a no-op once tenant_id is set.
--   * Sentinel UPDATE is the same — once stamped, subsequent runs see
--     non-NULL and skip.
--   * audit_logs is range-partitioned by created_at (V40/V57). UPDATE on
--     the partitioned root cascades to every partition automatically.
-- ---------------------------------------------------------------------------

BEGIN;

-- (1) Defensive re-run of V46 user-tenant backfill. Catches any rows that
--     slipped through between V46 and now where the writer fell through to
--     NULL (transient DB error, deleted user). Cheap if there are none.
UPDATE audit_logs AS al
SET    tenant_id = u.tenant_id
FROM   users u
WHERE  al.user_id = u.id
  AND  al.tenant_id IS NULL
  AND  u.tenant_id IS NOT NULL;

-- (2) Stamp remaining NULLs with the well-known "system" sentinel UUID.
--     These are truly anonymous events: failed-login attempts pre-auth,
--     /oauth2/token / /oauth2/authorize failures, PKCE failures, scheduled
--     jobs. The code-side change (AuditLogAdapter) will write this sentinel
--     directly from now on, so this UPDATE only repairs historical rows.
UPDATE audit_logs
   SET tenant_id = '00000000-0000-0000-0000-000000000000'
 WHERE tenant_id IS NULL;

-- Sanity log: report the post-backfill state for the audit trail.
DO $$
DECLARE
    remaining_null bigint;
    sentinel_count bigint;
    total          bigint;
BEGIN
    SELECT count(*) INTO remaining_null FROM audit_logs WHERE tenant_id IS NULL;
    SELECT count(*) INTO sentinel_count FROM audit_logs
     WHERE tenant_id = '00000000-0000-0000-0000-000000000000';
    SELECT count(*) INTO total FROM audit_logs;

    RAISE NOTICE 'V59 backfill complete. total=% sentinel=% remaining_null=%',
                 total, sentinel_count, remaining_null;
END $$;

COMMIT;
