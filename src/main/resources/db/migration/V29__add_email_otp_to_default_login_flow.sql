-- V29: Add EMAIL_OTP as step 2 to the system "Default Login" auth flow.
-- This enables 2FA for users who have enabled it in their settings.
-- Step 1 (PASSWORD) is handled by the login endpoint itself (seeded in V16).
-- Step 2 (EMAIL_OTP) is the secondary verification step shown by the frontend.
--
-- DISASTER-RECOVERY / FRESH-DB SAFETY (changed 2026-05-30):
-- The original V29 hardcoded two UUIDs that only exist on the long-running prod
-- DB (the system "Default Login" flow id e986943a-… and the EMAIL_OTP method id
-- 605de186-…). NEITHER is produced by any migration — V16 seeds the flow and the
-- auth_methods with gen_random_uuid() defaults, so on a from-zero `flyway migrate`
-- those ids do not exist and the INSERT violated auth_flow_steps_auth_flow_id_fkey,
-- breaking every DR rebuild from migrations alone. This rewrite resolves the flow
-- and the method by their STABLE NATURAL KEYS instead (system tenant + flow name +
-- operation_type; method type = 'EMAIL_OTP'), and is fully idempotent.
--
-- PROD IMPACT: NO-OP. On the existing prod DB the system "Default Login" flow
-- already has a step_order = 2 row, so the `WHERE NOT EXISTS` guard short-circuits
-- and zero rows are written. The resolved ids are identical to the previously
-- hardcoded ones (verified against prod). Because this edits an already-applied
-- migration, the stored checksum changes — a one-time `flyway repair` is required
-- on every existing DB BEFORE the next boot (validate-on-migrate=true in prod).
-- See docs/RUNBOOK_FLYWAY_V29_REPAIR.md.

INSERT INTO auth_flow_steps (auth_flow_id, auth_method_id, step_order, is_required, timeout_seconds, max_attempts)
SELECT
    af.id,        -- system "Default Login" flow (resolved by natural key)
    am.id,        -- EMAIL_OTP method (resolved by type)
    2,
    true,
    300,
    3
FROM auth_flows af
JOIN tenants t ON af.tenant_id = t.id
CROSS JOIN auth_methods am
WHERE t.name = 'system'
  AND af.name = 'Default Login'
  AND af.operation_type = 'APP_LOGIN'
  AND am.type = 'EMAIL_OTP'
  AND NOT EXISTS (
      SELECT 1 FROM auth_flow_steps existing
      WHERE existing.auth_flow_id = af.id
        AND existing.step_order = 2
  );
