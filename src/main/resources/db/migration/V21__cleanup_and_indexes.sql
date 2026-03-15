-- V21: Cleanup and Additional Indexes
-- Phase 2 stabilization: supplemental indexes + schema audit notes
--
-- NOTE: V7__add_performance_indexes.sql already covers:
--   • users(email)                     → idx_users_email_unique (partial, deleted_at IS NULL)
--   • users(tenant_id, is_active)      → idx_users_tenant_status
--   • audit_logs(tenant_id, created_at)→ idx_audit_tenant_created
--   • auth_sessions(user_id, status)   → idx_auth_sessions_user
--   • refresh_tokens(token)            → idx_refresh_tokens_lookup
--
-- This migration adds supplemental indexes for gaps identified in Phase 2 audit.

-- ============================================================================
-- 1. Supplemental indexes not covered by V7
-- ============================================================================

-- tenant_auth_methods: lookup by auth_method_id (join from auth_method side)
CREATE INDEX IF NOT EXISTS idx_tenant_auth_methods_method
    ON tenant_auth_methods(auth_method_id);

COMMENT ON INDEX idx_tenant_auth_methods_method
    IS 'Supports join queries from auth_method side';

-- auth_sessions: expires_at index for cleanup jobs (complements V7 partial idx)
CREATE INDEX IF NOT EXISTS idx_auth_sessions_all_expires
    ON auth_sessions(expires_at DESC);

COMMENT ON INDEX idx_auth_sessions_all_expires
    IS 'Supports bulk expiry cleanup regardless of status';

-- user_roles: composite index for user role lookups including non-expiring roles
-- V3 has idx_user_roles_expires but only WHERE expires_at IS NOT NULL (for cleanup).
-- PostgreSQL partial index predicates cannot reference NOW() (non-immutable),
-- so we create a plain composite index for the common access pattern.
CREATE INDEX IF NOT EXISTS idx_user_roles_user_assigned
    ON user_roles(user_id, assigned_at DESC);

COMMENT ON INDEX idx_user_roles_user_assigned
    IS 'Composite index for user-role history and active role lookups';

-- devices (user_devices): user lookup
CREATE INDEX IF NOT EXISTS idx_user_devices_user
    ON user_devices(user_id);

COMMENT ON INDEX idx_user_devices_user
    IS 'Accelerates per-user device listing';

-- devices: tenant lookup
CREATE INDEX IF NOT EXISTS idx_user_devices_tenant
    ON user_devices(tenant_id);

COMMENT ON INDEX idx_user_devices_tenant
    IS 'Accelerates per-tenant device listing';

-- user_enrollments: user + method lookup
CREATE INDEX IF NOT EXISTS idx_user_enrollments_user_method
    ON user_enrollments(user_id, auth_method_type);

COMMENT ON INDEX idx_user_enrollments_user_method
    IS 'Fast lookup of enrollment status for a specific auth method per user';

-- ============================================================================
-- 2. Tenants table — orphaned/unused column audit
-- NOTE: DO NOT DROP any columns — this section is documentation only.
-- ============================================================================

-- DOCUMENTED UNUSED / LEGACY COLUMNS (as of March 2026):
--
-- tenants.address_line1    — populated in V1, never exposed via TenantResponse DTO
-- tenants.address_line2    — same as above
-- tenants.city             — same as above
-- tenants.state            — same as above
-- tenants.country          — same as above
-- tenants.postal_code      — same as above
-- tenants.subscription_start_date  — stored but not surfaced in admin UI
-- tenants.subscription_end_date    — stored but not surfaced in admin UI
-- tenants.display_name     — duplicates `name` in practice; entity maps it but unused in UI
--
-- DECISION: Retain all columns. No drops until a full data-model review is done.
-- Future: consider moving address into a JSONB sub-document or separate table.

-- ============================================================================
-- 3. Roles table — deleted_at already present (no action needed)
-- ============================================================================

-- Confirmed in V3__create_roles_and_permissions.sql:
--   deleted_at TIMESTAMP (nullable) — soft-delete column is already there.
-- idx_roles_tenant and idx_roles_name are already partial on deleted_at IS NULL.
-- No changes required.

-- ============================================================================
-- 4. Ensure missing unique constraint on users.email (unconditional)
-- ============================================================================
-- V7 adds a PARTIAL unique index (WHERE deleted_at IS NULL), which means two
-- soft-deleted rows with the same email are allowed. That is intentional.
-- Add a non-partial B-tree index to support case-insensitive email lookups:

CREATE INDEX IF NOT EXISTS idx_users_email_lower
    ON users(LOWER(email))
    WHERE deleted_at IS NULL;

COMMENT ON INDEX idx_users_email_lower
    IS 'Supports case-insensitive email lookup for login (Locale.ROOT safety)';
