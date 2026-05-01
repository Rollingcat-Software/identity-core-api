-- V53: Defense-in-depth — forbid hard DELETE on users + tenants at the DB layer.
--
-- (Originally drafted as V51 on feat/v51-forbid-hard-delete-p1-7; renumbered to
--  V53 because V51/V52 were taken in the meantime by ShedLock + ShedLock TZ
--  alignment.)
--
-- Background:
--   On 2026-04-28 a careless `DELETE FROM users WHERE email = 'ahabgu@...'`
--   cascaded across ~13 child tables (webauthn_credentials, nfc_cards,
--   user_devices, totp_secrets, user_enrollments, mfa_sessions, sessions,
--   refresh_tokens, etc.) and wiped a real user's MFA enrollments.
--   Memory rule: feedback_no_hard_delete_users.md.
--
--   The application layer already enforces soft-delete:
--     * User.softDelete() sets deletedAt + status=INACTIVE (User.java:487-491).
--     * UserRepository.findByEmail filters `deletedAt IS NULL`.
--     * Tenant entity has @SQLDelete + @SQLRestriction (V49 documented the
--       contract; this trigger enforces it).
--
--   But the contract is enforceable only at the application layer — a
--   careless DBA, a `psql` session, or a future migration can still issue
--   a raw `DELETE FROM users` and cascade-wipe child tables. This trigger
--   blocks that path at the engine level.
--
-- Bypass for the legitimate hard-purge job (GDPR Art. 17 / KVKK):
--   SoftDeletePurgeJob.purgeBatch() permanently deletes rows whose
--   deletedAt is older than the 30-day retention window. That code path
--   sets a session-local GUC `app.allow_hard_delete = 'on'` inside its
--   transaction; the trigger consults the GUC and skips when bypass is
--   active. Because the GUC is set with SET LOCAL, it is automatically
--   reset at TX commit/rollback and cannot leak into other sessions.
--
-- Idempotent: CREATE OR REPLACE FUNCTION + DROP TRIGGER IF EXISTS guard
-- against re-runs (Flyway will only execute once, but defense-in-depth).

CREATE OR REPLACE FUNCTION forbid_hard_delete()
RETURNS TRIGGER AS $$
DECLARE
    bypass_flag TEXT;
BEGIN
    -- current_setting(name, missing_ok=true) returns NULL when the GUC is unset,
    -- avoiding 'unrecognized configuration parameter' errors.
    bypass_flag := current_setting('app.allow_hard_delete', true);
    IF bypass_flag = 'on' THEN
        RETURN OLD;   -- legitimate purge — allow the DELETE to proceed
    END IF;

    RAISE EXCEPTION
        'Hard DELETE forbidden on %: use soft-delete (set deleted_at) instead. '
        'Legitimate purge jobs must SET LOCAL app.allow_hard_delete = ''on'' '
        'inside their transaction. See V53 migration.', TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tg_users_forbid_hard_delete ON users;
CREATE TRIGGER tg_users_forbid_hard_delete
    BEFORE DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION forbid_hard_delete();

DROP TRIGGER IF EXISTS tg_tenants_forbid_hard_delete ON tenants;
CREATE TRIGGER tg_tenants_forbid_hard_delete
    BEFORE DELETE ON tenants
    FOR EACH ROW EXECUTE FUNCTION forbid_hard_delete();

COMMENT ON FUNCTION forbid_hard_delete() IS
    'BEFORE DELETE trigger guard for users + tenants. Raises restrict_violation '
    'unless app.allow_hard_delete=''on'' is SET LOCAL in the current TX. See V53.';
