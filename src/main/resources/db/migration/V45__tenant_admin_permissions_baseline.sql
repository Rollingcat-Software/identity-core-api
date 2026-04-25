-- V45: TENANT_ADMIN permission baseline (capture of 2026-04-24 live-ops)
--
-- Motivation:
--   On 2026-04-24, the Marmara TENANT_ADMIN dashboard was leaking 403/500/422
--   responses because:
--     (1) Several colon-form permissions used by RbacPermissionEvaluator
--         (auth_flow:read, device:read, enrollment:read, verification:read,
--         auth_method:read, audit:read) had not been seeded.
--     (2) The TENANT_ADMIN role's permission set was last seeded by V10 with
--         the dot-form names. The colon-form perms were never granted to it.
--     (3) Recovery was performed directly against the prod DB. This migration
--         captures that work so a fresh DB reproduces the fix and so future
--         tenants spawned from the system role template inherit the perms.
--
--   See feedback_audit_delta_before_rebuild.md for the recovery trail.
--
-- Strategy:
--   1. Insert the missing colon-form permission rows (idempotent).
--   2. Grant them to the system-template TENANT_ADMIN role
--      (20000000-0000-0000-0000-000000000001) so future tenants spawned via
--      default_role_templates inherit them automatically.
--   3. Mirror the grant to every EXISTING tenant TENANT_ADMIN role row, so
--      already-provisioned tenants (Marmara, Istanbul Tech, etc.) catch up.
--   4. Defensively bump user_type to TENANT_ADMIN for any user assigned a
--      TENANT_ADMIN role but still flagged TENANT_MEMBER — this is what
--      RbacAuthorizationService.isTenantAdmin() reads.
--
-- Idempotent: every INSERT uses ON CONFLICT DO NOTHING. The migration is
-- safe to apply repeatedly on the same DB.

-- ============================================================================
-- 1. Insert colon-form permissions if missing
-- ============================================================================
--
-- The dot-form (audit.view, etc.) was V3's convention. RbacPermissionEvaluator
-- since 2026-03 builds permission strings as "{resource}:{action}" — and
-- @rbac.hasPermission('audit:read') will only resolve if the row exists with
-- exactly that name. The 5 colon-form *_:read perms were created during the
-- 2026-04-24 hotfix; audit:read was attempted but failed due to NOT NULL on
-- permissions.resource. This migration includes that resource value.

INSERT INTO permissions (name, resource, action, description) VALUES
    ('audit:read',         'audit',        'read',      'View audit log entries'),
    ('auth_flow:read',     'auth_flow',    'read',      'View tenant auth flow configurations'),
    ('auth_flow:create',   'auth_flow',    'create',    'Create tenant auth flow configurations'),
    ('auth_flow:update',   'auth_flow',    'update',    'Modify tenant auth flow configurations'),
    ('auth_flow:delete',   'auth_flow',    'delete',    'Delete tenant auth flow configurations'),
    ('auth_method:read',   'auth_method',  'read',      'View available auth methods'),
    ('auth_method:configure','auth_method','configure', 'Configure tenant-specific auth method options'),
    ('device:read',        'device',       'read',      'View enrolled devices'),
    ('device:register',    'device',       'register',  'Register new trusted devices'),
    ('device:delete',      'device',       'delete',    'Revoke / unregister devices'),
    ('enrollment:read',    'enrollment',   'read',      'View biometric enrollments'),
    ('enrollment:create',  'enrollment',   'create',    'Enroll new biometric data'),
    ('enrollment:delete',  'enrollment',   'delete',    'Delete biometric enrollments'),
    ('verification:read',  'verification', 'read',      'View verification flows / sessions'),
    ('verification:create','verification', 'create',    'Initiate verification sessions'),
    ('verification:update','verification', 'update',    'Update verification configuration')
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- 2. Grant baseline TENANT_ADMIN permissions to the system role template
-- ============================================================================
--
-- The system-template TENANT_ADMIN role lives under tenant_id = '00000000-...'
-- and is the source of permissions copied to every tenant TENANT_ADMIN role
-- at provisioning time. Granting here means future tenants inherit the perms.

INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000001'::uuid, p.id
FROM permissions p
WHERE p.name IN (
        'audit:read',
        'auth_flow:read',     'auth_flow:create',  'auth_flow:update',  'auth_flow:delete',
        'auth_method:read',   'auth_method:configure',
        'device:read',        'device:register',   'device:delete',
        'enrollment:read',    'enrollment:create', 'enrollment:delete',
        'verification:read',  'verification:create','verification:update'
      )
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ============================================================================
-- 3. Mirror to every existing tenant TENANT_ADMIN role
-- ============================================================================
--
-- For DBs already provisioned with tenants (Marmara, etc.) before V45 lands,
-- copy the colon-form perms to their tenant-scoped TENANT_ADMIN role rows
-- so isTenantAdmin() + hasPermission() resolve consistently.

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'TENANT_ADMIN'
  AND r.tenant_id IS NOT NULL
  AND r.tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid
  AND p.name IN (
        'audit:read',
        'auth_flow:read',     'auth_flow:create',  'auth_flow:update',  'auth_flow:delete',
        'auth_method:read',   'auth_method:configure',
        'device:read',        'device:register',   'device:delete',
        'enrollment:read',    'enrollment:create', 'enrollment:delete',
        'verification:read',  'verification:create','verification:update'
      )
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- ============================================================================
-- 4. Defensively sync user_type for users assigned a TENANT_ADMIN role
-- ============================================================================
--
-- RbacAuthorizationService.isTenantAdmin() reads users.user_type, NOT the
-- role-assignment chain. A user can hold a TENANT_ADMIN role while still
-- having user_type = 'TENANT_MEMBER' (this is what trapped Ahmet on
-- 2026-04-24). Sync the column so the two signals do not diverge.
--
-- Scope: only users currently assigned the system-template OR a tenant-scoped
-- TENANT_ADMIN role. ROOT users are left alone (they outrank TENANT_ADMIN).

UPDATE users u
SET user_type = 'TENANT_ADMIN',
    updated_at = CURRENT_TIMESTAMP
WHERE u.user_type = 'TENANT_MEMBER'
  AND EXISTS (
      SELECT 1
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = u.id
        AND r.name = 'TENANT_ADMIN'
        AND r.is_active = TRUE
  );

-- ============================================================================
-- 5. Documentation
-- ============================================================================

COMMENT ON COLUMN permissions.name IS
    'Canonical permission identifier. Colon-form ("{resource}:{action}") is the
    convention used by RbacPermissionEvaluator since 2026-03; older dot-form
    rows are retained for backwards compatibility. New permissions should use
    colon-form.';
