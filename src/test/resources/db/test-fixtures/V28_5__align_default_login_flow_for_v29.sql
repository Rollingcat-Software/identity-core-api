-- ============================================================================
-- TEST-ONLY MIGRATION (loaded only by Testcontainers integration profile via
-- spring.flyway.locations=classpath:db/migration,classpath:db/test-fixtures).
-- This file is NOT on the production classpath; it never runs in prod.
-- ============================================================================
--
-- WHY THIS EXISTS
-- ---------------
-- V29__add_email_otp_to_default_login_flow.sql inserts into auth_flow_steps
-- with two HARDCODED UUIDs:
--   * auth_flow_id  = 'e986943a-3646-4820-8943-8260ed55cbb8'  (Default Login)
--   * auth_method_id = '605de186-6887-455b-b6d1-035e9f26b406' (EMAIL_OTP)
--
-- However, V16__auth_flow_system.sql seeds those rows with random UUIDs via
--   id UUID PRIMARY KEY DEFAULT gen_random_uuid()
-- so the hardcoded UUIDs in V29 never match a real row on a fresh DB.
--
-- On production the V29 migration is recorded as SUCCESS in
-- flyway_schema_history (its INSERT was a silent no-op because step_order=2
-- happened to already exist for the actual Default Login flow id, OR the
-- hardcoded UUIDs were back-filled by hand long ago — either way prod is
-- consistent today). On a fresh Testcontainers DB the same INSERT raises:
--   ERROR: insert or update on table "auth_flow_steps" violates foreign key
--   constraint "auth_flow_steps_auth_flow_id_fkey"
-- because the hardcoded auth_flow_id has no parent row.
--
-- WHY WE ARE NOT EDITING V29 IN PLACE
-- -----------------------------------
-- V29 is in production's flyway_schema_history with a fixed checksum and
-- our prod profile keeps Flyway's default validate-on-migrate=true. Editing
-- V29's body would force a checksum mismatch and a manual `flyway repair`
-- on prod. A test-only fixture has zero prod surface area.
--
-- WHAT THIS FIXTURE DOES
-- ----------------------
-- Re-keys the V16-seeded "Default Login" auth_flow row and the EMAIL_OTP
-- auth_methods row to the UUIDs that V29 expects, BEFORE V29 runs. After
-- this fixture:
--   * auth_flows       has id=e986943a... for system tenant's Default Login
--   * auth_methods     has id=605de186... for EMAIL_OTP
--   * auth_flow_steps  has step_order=1 (PASSWORD) wired to the new flow id
-- so V29's INSERT references real parent rows and either inserts step 2 or
-- no-ops via its WHERE NOT EXISTS guard.
--
-- This is idempotent — safe to re-run, but in practice runs exactly once in
-- a fresh container per CI job.
-- ============================================================================

-- 1. Drop the V16-seeded PASSWORD step row first so that the auth_flows.id
--    UPDATE doesn't trip the auth_flow_steps_auth_flow_id_fkey ON UPDATE
--    NO ACTION default. ON DELETE CASCADE means we can safely delete the
--    step here; we recreate it at the bottom of this script.
DELETE FROM auth_flow_steps
WHERE auth_flow_id IN (
    SELECT af.id
    FROM auth_flows af
    JOIN tenants t ON t.id = af.tenant_id
    WHERE t.name = 'system'
      AND af.name = 'Default Login'
);

-- 2. Re-key the Default Login auth_flow row to the UUID V29 hardcodes.
UPDATE auth_flows
SET id = 'e986943a-3646-4820-8943-8260ed55cbb8'
WHERE name = 'Default Login'
  AND tenant_id = (SELECT id FROM tenants WHERE name = 'system')
  AND id <> 'e986943a-3646-4820-8943-8260ed55cbb8';

-- 3. Re-key the EMAIL_OTP auth_methods row to the UUID V29 hardcodes.
--    No FK references to this row exist at the V28 stage (verified by
--    grepping V16-V28; tenant_auth_methods only seeds PASSWORD), so the
--    UPDATE will not violate ON UPDATE NO ACTION.
UPDATE auth_methods
SET id = '605de186-6887-455b-b6d1-035e9f26b406'
WHERE type = 'EMAIL_OTP'
  AND id <> '605de186-6887-455b-b6d1-035e9f26b406';

-- 4. Recreate the PASSWORD step 1 against the now-canonical auth_flow_id.
INSERT INTO auth_flow_steps (
    auth_flow_id, auth_method_id, step_order,
    is_required, timeout_seconds, max_attempts
)
SELECT
    'e986943a-3646-4820-8943-8260ed55cbb8',
    am.id,
    1, true, 120, 5
FROM auth_methods am
WHERE am.type = 'PASSWORD'
ON CONFLICT ON CONSTRAINT uq_flow_step_order DO NOTHING;
