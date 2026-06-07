-- V84: tenant_id on user_settings — defense-in-depth tenant isolation.
--
-- Motivation (authz cross-tenant IDOR fix, 2026-06-07):
--   GET/PUT /api/v1/users/{userId}/settings (+ the notifications/security/
--   appearance sub-resources) were gated only by
--     hasPermission(#userId, 'user_settings', read|write) OR isCurrentUser(#userId)
--   The hasPermission(...) SpEL routes through RbacPermissionEvaluator, which
--   IGNORES the #userId target (it only checks "does the caller hold
--   user_settings:read?"). A TENANT_ADMIN holds every tenant-scoped permission
--   implicitly, so a TENANT_ADMIN of tenant A could read/write — including the
--   `security` section — the settings of ANY user in ANY tenant. user_settings
--   had NO tenant column, so unlike the 8 entities hardened in P0-1 it carried no
--   @Filter(tenantFilter) DB backstop either.
--
--   The IMMEDIATE mitigation is the application-layer object guard
--   (UserController.assertCanAccessUserSettings). THIS migration adds the
--   defense-in-depth column so UserSettings can also carry @Filter(tenantFilter),
--   matching AuditLog/AuthSession/UserEnrollment/etc.
--
-- Shape:
--   * Add NULLABLE tenant_id (so the additive ALTER is metadata-only and the
--     existing single-statement write path is never broken by a NOT NULL gap).
--   * Backfill from the owning users row.
--   * FK → tenants(id) ON DELETE CASCADE (a tenant teardown removes its rows).
--   * Index on tenant_id (the @Filter predicate column).
-- Idempotent — IF NOT EXISTS / guarded constraint add, safe to replay.

ALTER TABLE user_settings
    ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Backfill: each settings row belongs to the tenant of its owning user.
UPDATE user_settings us
SET tenant_id = u.tenant_id
FROM users u
WHERE us.user_id = u.id
  AND us.tenant_id IS NULL;

-- FK to tenants. Guarded so a replay does not error on the existing constraint.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'user_settings'
          AND constraint_name = 'fk_user_settings_tenant'
    ) THEN
        ALTER TABLE user_settings
            ADD CONSTRAINT fk_user_settings_tenant
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_user_settings_tenant_id ON user_settings (tenant_id);

COMMENT ON COLUMN user_settings.tenant_id IS
    'Owning tenant (mirrors users.tenant_id of user_id). Backs the Hibernate '
    '@Filter(tenantFilter) defense-in-depth on UserSettings. Nullable so the '
    'additive migration is metadata-only; the application-layer guard '
    '(UserController.assertCanAccessUserSettings) is the primary cross-tenant '
    'control. See docs/findings/2026-06-07-authz-idor-fixes.md.';
