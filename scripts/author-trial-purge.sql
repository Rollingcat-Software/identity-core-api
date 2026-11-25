-- Author-trial data deletion (Paper B, V90) — the ONE documented command.
--
--   psql "$DATABASE_URL" -v tenant_id='<trial-tenant-uuid>' \
--        -f scripts/author-trial-purge.sql
--
-- What it does, in one transaction:
--   1. Enqueues FACE + VOICE biometric-template deletions for every bound trial
--      account (biometric_deletion_outbox, V87). BiometricDeletionOutboxWorker
--      drains them through the biometric-processor within ~60 s; a 404 means
--      nothing was enrolled. The intent survives a later hard purge.
--   2. Soft-deletes the bound accounts exactly as ManageUserService.deleteUser
--      does (users.deleted_at, status INACTIVE, is_active=false). It NEVER hard
--      deletes users (the V53 trigger forbids it) and never touches the tenant.
--   3. Deletes every author-trial attempt, plan slot and participant row for the
--      tenant.
--
-- Idempotent: re-running it enqueues nothing new (unique user_id+method), skips
-- already deleted users and deletes zero rows. The signed paper/analysis data
-- is not in this database; the coordinator must delete local exports separately
-- (see docs/AUTHOR_TRIAL.md, retention).

\set ON_ERROR_STOP on

BEGIN;

-- 1. Biometric-template deletion intents (idempotent via the unique key).
INSERT INTO biometric_deletion_outbox (id, user_id, tenant_id, method, created_at, attempts)
SELECT gen_random_uuid(), p.user_id, p.tenant_id, m.method, NOW(), 0
  FROM author_trial_participants p
 CROSS JOIN (VALUES ('FACE'), ('VOICE')) AS m(method)
 WHERE p.tenant_id = :'tenant_id'::uuid
ON CONFLICT (user_id, method) DO NOTHING;

-- 2. Soft-delete the bound accounts (the V53 trigger forbids a hard delete).
UPDATE users u
   SET deleted_at = NOW(),
       status = 'INACTIVE',
       is_active = false
 WHERE u.id IN (SELECT p.user_id FROM author_trial_participants p
                 WHERE p.tenant_id = :'tenant_id'::uuid)
   AND u.deleted_at IS NULL;

-- 3. The trial log and its configuration.
DELETE FROM author_trial_attempts      WHERE tenant_id = :'tenant_id'::uuid;
DELETE FROM author_trial_plan_entries  WHERE tenant_id = :'tenant_id'::uuid;
DELETE FROM author_trial_participants  WHERE tenant_id = :'tenant_id'::uuid;

COMMIT;

-- Verify: the participant/attempt/plan tables must be empty for this tenant.
--   SELECT COUNT(*) FROM author_trial_participants WHERE tenant_id = '<uuid>';
--   SELECT COUNT(*) FROM author_trial_attempts     WHERE tenant_id = '<uuid>';
--   SELECT COUNT(*) FROM author_trial_plan_entries WHERE tenant_id = '<uuid>';
-- Then confirm the outbox drained:
--   SELECT method, completed_at, attempts, last_error
--     FROM biometric_deletion_outbox WHERE tenant_id = '<uuid>';