-- V49: Tenant soft-delete contract — defense-in-depth (EDGE-P1 #5)
--
-- Background:
--   tenants.id is referenced by ~13 child tables (users, roles, auth_flows,
--   tenant_email_domains, oauth2_clients, api_keys, nfc_cards, mfa_audit_log,
--   verification_sessions, audit_logs, sessions, etc.). Most are
--   ON DELETE CASCADE — a hard `DELETE FROM tenants` would silently wipe
--   ~10 dependent tables (same lesson as
--   feedback_no_hard_delete_users.md, applied at tenant level).
--
-- Contract:
--   * `tenants.deleted_at` (already added in V1) is the soft-delete tombstone.
--   * Hibernate `@SQLDelete` on the Tenant entity rewrites JPA `delete*` to
--     `UPDATE tenants SET deleted_at = NOW() WHERE id = ?`.
--   * `@SQLRestriction("deleted_at IS NULL")` filters JPA finds.
--   * Hard `DELETE FROM tenants` is FORBIDDEN at the application layer.
--     This migration documents the contract via column comment so DBAs
--     reviewing the schema do not re-introduce hard-delete code paths.
--
-- This migration is idempotent — re-running it is a no-op.

-- Reverse-direction index for soft-delete audit / restore queries.
-- Covers `WHERE deleted_at IS NOT NULL` lookups (e.g. listing all
-- soft-deleted tenants for an admin restore screen). The pre-existing
-- partial indexes (idx_tenants_name, idx_tenants_domain, etc.) all gate
-- on `deleted_at IS NULL` and therefore exclude tombstoned rows by design.
CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at
    ON tenants (deleted_at)
    WHERE deleted_at IS NOT NULL;

-- Document the soft-delete contract on the column itself so any future
-- developer reading the schema sees the constraint at the source.
COMMENT ON COLUMN tenants.deleted_at IS
    'Soft-delete tombstone. NULL = active. NON-NULL = soft-deleted. '
    'Hard DELETE is forbidden — would CASCADE-wipe ~10 child tables. '
    'JPA enforces this via @SQLDelete + @SQLRestriction on Tenant entity. '
    'Use ManageTenantService.softDeleteTenant(id). See V49 migration.';
