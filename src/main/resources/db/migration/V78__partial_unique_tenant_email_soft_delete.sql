-- V78: make the (tenant_id, email) uniqueness SOFT-DELETE-AWARE.
--
-- Problem (prod 500 on guest-accept / re-registration, 2026-06-01):
--   The legacy `unique_tenant_email` UNIQUE(tenant_id, email) (V2) covered
--   ALL rows, including soft-deleted ones (deleted_at IS NOT NULL). But the
--   application guard `UserRepository.existsByEmail(...)` respects the entity's
--   @SQLRestriction("deleted_at IS NULL") (PR #70), so a soft-deleted user
--   PASSED the guard and then COLLIDED with this constraint on INSERT —
--   surfacing as an opaque DataIntegrityViolation 500 when a previously-removed
--   email (e.g. a deleted-then-re-invited guest) tried to register again.
--
-- Fix: replace the full constraint with a PARTIAL unique index scoped to LIVE
--   rows, so the constraint and the guard agree:
--     * active  (tenant_id, email) stays unique  → real duplicates still 409 via the guard;
--     * a soft-deleted (tenant_id, email) no longer blocks a fresh registration.
--
-- Safe + idempotent: the old constraint guaranteed global (tenant_id, email)
--   uniqueness, so the LIVE subset is already unique → the partial unique index
--   builds without violation. Mirrors the existing soft-delete-aware partial
--   indexes on this table (idx_users_email_unique, idx_users_tenant_email).

ALTER TABLE users DROP CONSTRAINT IF EXISTS unique_tenant_email;

CREATE UNIQUE INDEX IF NOT EXISTS unique_tenant_email_active
    ON users (tenant_id, email)
    WHERE deleted_at IS NULL;
