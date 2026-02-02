-- V10: RBAC Redesign - User Types, Guest Lifecycle, and Enhanced Permissions
-- Introduces hierarchical user types: ROOT, TENANT_ADMIN, TENANT_MEMBER, GUEST
-- Adds guest invitation tracking and auto-expiration support

-- ============================================================================
-- 1. Add UserType to Users Table
-- ============================================================================

-- Create user_type enum
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_type_enum') THEN
        CREATE TYPE user_type_enum AS ENUM ('ROOT', 'TENANT_ADMIN', 'TENANT_MEMBER', 'GUEST');
    END IF;
END$$;

-- Add user_type column (default TENANT_MEMBER for existing users)
ALTER TABLE users ADD COLUMN IF NOT EXISTS user_type VARCHAR(20) NOT NULL DEFAULT 'TENANT_MEMBER';

-- Add guest lifecycle columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by UUID REFERENCES users(id);

-- Index for guest expiration cleanup
CREATE INDEX IF NOT EXISTS idx_users_expires_at
    ON users (expires_at)
    WHERE expires_at IS NOT NULL AND deleted_at IS NULL;

-- Index for user type queries
CREATE INDEX IF NOT EXISTS idx_users_user_type
    ON users (user_type)
    WHERE deleted_at IS NULL;

-- Index for invited_by lookups
CREATE INDEX IF NOT EXISTS idx_users_invited_by
    ON users (invited_by)
    WHERE invited_by IS NOT NULL;

-- Composite index for tenant + user_type queries
CREATE INDEX IF NOT EXISTS idx_users_tenant_user_type
    ON users (tenant_id, user_type)
    WHERE deleted_at IS NULL;

-- ============================================================================
-- 2. Guest Invitations Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS guest_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    invited_by UUID NOT NULL REFERENCES users(id),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Invitation lifecycle
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    invitation_token VARCHAR(512) UNIQUE,
    message TEXT,

    -- Time constraints
    expires_at TIMESTAMP NOT NULL,
    access_starts_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    access_ends_at TIMESTAMP NOT NULL,

    -- Metadata
    max_extensions INT DEFAULT 0,
    extension_count INT DEFAULT 0,
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    accepted_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Constraints
    CONSTRAINT chk_guest_invitation_status
        CHECK (status IN ('PENDING', 'ACCEPTED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT chk_guest_access_window
        CHECK (access_ends_at > access_starts_at),
    CONSTRAINT chk_guest_invitation_expiry
        CHECK (expires_at > created_at)
);

-- Indexes for guest_invitations
CREATE INDEX IF NOT EXISTS idx_guest_invitations_tenant
    ON guest_invitations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_guest_invitations_email
    ON guest_invitations (email);
CREATE INDEX IF NOT EXISTS idx_guest_invitations_status
    ON guest_invitations (status)
    WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_guest_invitations_token
    ON guest_invitations (invitation_token)
    WHERE invitation_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_guest_invitations_access_ends
    ON guest_invitations (access_ends_at)
    WHERE status = 'ACCEPTED';
CREATE UNIQUE INDEX IF NOT EXISTS idx_guest_invitations_active_email
    ON guest_invitations (tenant_id, email)
    WHERE status IN ('PENDING', 'ACCEPTED');

-- Trigger for updated_at
CREATE TRIGGER update_guest_invitations_updated_at
    BEFORE UPDATE ON guest_invitations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 3. Default Role Templates Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS default_role_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_type VARCHAR(20) NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    is_removable BOOLEAN DEFAULT TRUE NOT NULL,
    priority INT DEFAULT 0 NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT chk_default_role_user_type
        CHECK (user_type IN ('ROOT', 'TENANT_ADMIN', 'TENANT_MEMBER', 'GUEST')),
    CONSTRAINT unique_user_type_role_tenant
        UNIQUE (user_type, role_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_default_role_templates_type
    ON default_role_templates (user_type);
CREATE INDEX IF NOT EXISTS idx_default_role_templates_tenant
    ON default_role_templates (tenant_id);

-- ============================================================================
-- 4. Add New Permissions
-- ============================================================================

INSERT INTO permissions (name, description, resource, action) VALUES
    -- Permission management
    ('permission.read', 'Read permission definitions', 'permission', 'read'),
    ('permission.create', 'Create new permission types', 'permission', 'create'),
    ('permission.update', 'Update permission definitions', 'permission', 'update'),
    ('permission.delete', 'Delete permission types', 'permission', 'delete'),

    -- Guest management
    ('guest.invite', 'Invite guest users', 'guest', 'invite'),
    ('guest.revoke', 'Revoke guest access', 'guest', 'revoke'),
    ('guest.read', 'View guest users and invitations', 'guest', 'read'),
    ('guest.extend', 'Extend guest access duration', 'guest', 'extend'),

    -- User-role assignment management
    ('user_role.assign', 'Assign roles to users', 'user_role', 'assign'),
    ('user_role.revoke', 'Revoke roles from users', 'user_role', 'revoke'),
    ('user_role.read', 'View user role assignments', 'user_role', 'read'),

    -- System-level (ROOT only)
    ('tenant.create', 'Create new tenants', 'tenant', 'create'),
    ('system.configure', 'Configure system-wide settings', 'system', 'configure'),
    ('system.audit', 'Access system-wide audit logs', 'system', 'audit'),

    -- Tenant configuration
    ('tenant.configure', 'Configure tenant settings', 'tenant', 'configure'),
    ('tenant.members', 'Manage tenant membership', 'tenant', 'members')
ON CONFLICT (resource, action) DO NOTHING;

-- ============================================================================
-- 5. Add New System Roles
-- ============================================================================

-- TENANT_FULL_ACCESS: Default role for TENANT_ADMIN
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active)
VALUES (
    '20000000-0000-0000-0000-000000000005',
    '00000000-0000-0000-0000-000000000000',
    'TENANT_FULL_ACCESS',
    'Full access within tenant scope - default for Tenant Admins',
    TRUE, TRUE
) ON CONFLICT (tenant_id, name) DO NOTHING;

-- TENANT_EDITOR: Full read + write within tenant (no admin functions)
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active)
VALUES (
    '20000000-0000-0000-0000-000000000006',
    '00000000-0000-0000-0000-000000000000',
    'TENANT_EDITOR',
    'Read and write access within tenant - no admin functions',
    TRUE, TRUE
) ON CONFLICT (tenant_id, name) DO NOTHING;

-- TENANT_VIEWER: Read-only access (default for TENANT_MEMBER)
-- Already exists as 'VIEWER' (20000000-0000-0000-0000-000000000004)
-- We keep it and also add TENANT_VIEWER as an alias
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active)
VALUES (
    '20000000-0000-0000-0000-000000000007',
    '00000000-0000-0000-0000-000000000000',
    'TENANT_VIEWER',
    'Read-only access within tenant - default for Tenant Members',
    TRUE, TRUE
) ON CONFLICT (tenant_id, name) DO NOTHING;

-- GUEST_ACCESS: Minimal access role for guests (empty by default)
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active)
VALUES (
    '20000000-0000-0000-0000-000000000008',
    '00000000-0000-0000-0000-000000000000',
    'GUEST_ACCESS',
    'Minimal guest access - no permissions by default, must be granted by Tenant Admin',
    TRUE, TRUE
) ON CONFLICT (tenant_id, name) DO NOTHING;

-- ============================================================================
-- 6. Assign Permissions to New Roles
-- ============================================================================

-- TENANT_FULL_ACCESS: All tenant-scoped permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000005', id
FROM permissions
WHERE resource IN ('user', 'role', 'biometric', 'analytics', 'audit', 'guest', 'user_role', 'permission', 'tenant')
  AND name NOT IN ('tenant.create', 'system.configure', 'system.audit')
ON CONFLICT DO NOTHING;

-- TENANT_EDITOR: Read + write on data, no admin functions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000006', id
FROM permissions
WHERE name IN (
    'user.read', 'user.create', 'user.update',
    'biometric.enroll', 'biometric.verify',
    'role.read',
    'analytics.view',
    'user_role.read',
    'guest.read'
)
ON CONFLICT DO NOTHING;

-- TENANT_VIEWER: Read-only permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000007', id
FROM permissions
WHERE name IN (
    'user.read',
    'role.read',
    'analytics.view',
    'audit.view',
    'user_role.read',
    'guest.read',
    'permission.read',
    'tenant.read'
)
ON CONFLICT DO NOTHING;

-- GUEST_ACCESS: No permissions by default (empty role)
-- Tenant Admin grants specific permissions as needed

-- Update SUPER_ADMIN to include all new permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '10000000-0000-0000-0000-000000000001', id
FROM permissions
WHERE id NOT IN (
    SELECT permission_id FROM role_permissions WHERE role_id = '10000000-0000-0000-0000-000000000001'
)
ON CONFLICT DO NOTHING;

-- Update TENANT_ADMIN role with new permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000001', id
FROM permissions
WHERE resource IN ('guest', 'user_role', 'permission', 'tenant')
  AND name NOT IN ('tenant.create', 'system.configure', 'system.audit')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 7. Insert Default Role Templates
-- ============================================================================

-- ROOT: Gets SUPER_ADMIN role (non-removable)
INSERT INTO default_role_templates (user_type, role_id, tenant_id, is_removable, priority)
VALUES ('ROOT', '10000000-0000-0000-0000-000000000001', NULL, FALSE, 100)
ON CONFLICT (user_type, role_id, tenant_id) DO NOTHING;

-- TENANT_ADMIN: Gets TENANT_FULL_ACCESS + TENANT_ADMIN roles
INSERT INTO default_role_templates (user_type, role_id, tenant_id, is_removable, priority)
VALUES
    ('TENANT_ADMIN', '20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', FALSE, 90),
    ('TENANT_ADMIN', '20000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000000', FALSE, 89)
ON CONFLICT (user_type, role_id, tenant_id) DO NOTHING;

-- TENANT_MEMBER: Gets TENANT_VIEWER role (removable - admin can change)
INSERT INTO default_role_templates (user_type, role_id, tenant_id, is_removable, priority)
VALUES ('TENANT_MEMBER', '20000000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-000000000000', TRUE, 50)
ON CONFLICT (user_type, role_id, tenant_id) DO NOTHING;

-- GUEST: Gets GUEST_ACCESS role (minimal, no permissions)
INSERT INTO default_role_templates (user_type, role_id, tenant_id, is_removable, priority)
VALUES ('GUEST', '20000000-0000-0000-0000-000000000008', '00000000-0000-0000-0000-000000000000', TRUE, 10)
ON CONFLICT (user_type, role_id, tenant_id) DO NOTHING;

-- ============================================================================
-- 8. Update Existing System Admin to ROOT type
-- ============================================================================

UPDATE users SET user_type = 'ROOT'
WHERE email = 'admin@fivucsas.local'
  AND user_type = 'TENANT_MEMBER';

-- ============================================================================
-- 9. Stored Procedures for Guest Lifecycle
-- ============================================================================

-- Function to expire and clean up guest users
CREATE OR REPLACE FUNCTION cleanup_expired_guests()
RETURNS INTEGER AS $$
DECLARE
    affected_count INTEGER;
BEGIN
    -- Soft-delete expired guest users
    UPDATE users
    SET deleted_at = CURRENT_TIMESTAMP,
        status = 'INACTIVE',
        updated_at = CURRENT_TIMESTAMP
    WHERE user_type = 'GUEST'
      AND expires_at IS NOT NULL
      AND expires_at < CURRENT_TIMESTAMP
      AND deleted_at IS NULL;

    GET DIAGNOSTICS affected_count = ROW_COUNT;

    -- Expire pending invitations past their expiry
    UPDATE guest_invitations
    SET status = 'EXPIRED',
        updated_at = CURRENT_TIMESTAMP
    WHERE status = 'PENDING'
      AND expires_at < CURRENT_TIMESTAMP;

    -- Expire accepted invitations past their access window
    UPDATE guest_invitations
    SET status = 'EXPIRED',
        updated_at = CURRENT_TIMESTAMP
    WHERE status = 'ACCEPTED'
      AND access_ends_at < CURRENT_TIMESTAMP;

    -- Delete user_roles for expired guests
    DELETE FROM user_roles
    WHERE user_id IN (
        SELECT id FROM users
        WHERE user_type = 'GUEST'
          AND deleted_at IS NOT NULL
    );

    -- Revoke refresh tokens for expired guests
    UPDATE refresh_tokens
    SET is_revoked = TRUE,
        revoked_at = CURRENT_TIMESTAMP,
        revoked_reason = 'GUEST_EXPIRED'
    WHERE user_id IN (
        SELECT id FROM users
        WHERE user_type = 'GUEST'
          AND deleted_at IS NOT NULL
    )
    AND is_revoked = FALSE;

    RETURN affected_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 10. Comments
-- ============================================================================

COMMENT ON COLUMN users.user_type IS 'Hierarchical user type: ROOT > TENANT_ADMIN > TENANT_MEMBER > GUEST';
COMMENT ON COLUMN users.expires_at IS 'Account expiration time (used for GUEST users)';
COMMENT ON COLUMN users.invited_by IS 'User who invited this user (used for GUEST users)';
COMMENT ON TABLE guest_invitations IS 'Tracks guest user invitations with time-bounded access';
COMMENT ON TABLE default_role_templates IS 'Maps user types to their default role assignments';
COMMENT ON FUNCTION cleanup_expired_guests IS 'Scheduled cleanup of expired guest users and their associated data';
