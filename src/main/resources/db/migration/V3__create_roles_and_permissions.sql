-- V3: Create Roles and Permissions Tables
-- Role-Based Access Control (RBAC) implementation

-- Permissions Table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT unique_resource_action UNIQUE (resource, action)
);

-- Roles Table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,

    CONSTRAINT unique_tenant_role_name UNIQUE (tenant_id, name)
);

-- Role-Permission Mapping
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    granted_by UUID REFERENCES users(id),

    PRIMARY KEY (role_id, permission_id)
);

-- User-Role Mapping
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    assigned_by UUID REFERENCES users(id),
    expires_at TIMESTAMP,

    PRIMARY KEY (user_id, role_id)
);

-- Indexes
CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_permissions_resource ON permissions(resource);
CREATE INDEX idx_roles_tenant ON roles(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_name ON roles(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- Comments
COMMENT ON TABLE permissions IS 'System permissions for access control';
COMMENT ON TABLE roles IS 'User roles for RBAC';
COMMENT ON TABLE role_permissions IS 'Mapping of permissions to roles';
COMMENT ON TABLE user_roles IS 'Assignment of roles to users';

-- Triggers
CREATE TRIGGER update_permissions_updated_at BEFORE UPDATE ON permissions
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action) VALUES
    -- User permissions
    ('user.read', 'Read user information', 'user', 'read'),
    ('user.create', 'Create new users', 'user', 'create'),
    ('user.update', 'Update user information', 'user', 'update'),
    ('user.delete', 'Delete users', 'user', 'delete'),

    -- Biometric permissions
    ('biometric.enroll', 'Enroll biometric data', 'biometric', 'enroll'),
    ('biometric.verify', 'Verify biometric data', 'biometric', 'verify'),
    ('biometric.delete', 'Delete biometric data', 'biometric', 'delete'),

    -- Role permissions
    ('role.read', 'Read roles', 'role', 'read'),
    ('role.create', 'Create roles', 'role', 'create'),
    ('role.update', 'Update roles', 'role', 'update'),
    ('role.delete', 'Delete roles', 'role', 'delete'),

    -- Tenant permissions
    ('tenant.read', 'Read tenant information', 'tenant', 'read'),
    ('tenant.update', 'Update tenant information', 'tenant', 'update'),
    ('tenant.delete', 'Delete tenant', 'tenant', 'delete'),

    -- Analytics permissions
    ('analytics.view', 'View analytics and reports', 'analytics', 'view'),
    ('audit.view', 'View audit logs', 'audit', 'view')
ON CONFLICT DO NOTHING;

-- Insert default system roles
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active) VALUES
    -- Global system roles
    ('10000000-0000-0000-0000-000000000001', NULL, 'SUPER_ADMIN', 'Super administrator with full system access', TRUE, TRUE),
    ('10000000-0000-0000-0000-000000000002', NULL, 'SYSTEM', 'System-level role for internal operations', TRUE, TRUE),

    -- Tenant-level roles (for system tenant as template)
    ('20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'TENANT_ADMIN', 'Tenant administrator', TRUE, TRUE),
    ('20000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000000', 'TENANT_MANAGER', 'Tenant manager', TRUE, TRUE),
    ('20000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000000', 'USER', 'Regular user', TRUE, TRUE),
    ('20000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000000', 'VIEWER', 'Read-only viewer', TRUE, TRUE)
ON CONFLICT DO NOTHING;

-- Assign all permissions to SUPER_ADMIN
INSERT INTO role_permissions (role_id, permission_id)
SELECT '10000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- Assign tenant admin permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000001', id FROM permissions
WHERE resource IN ('user', 'role', 'biometric', 'analytics', 'audit')
ON CONFLICT DO NOTHING;

-- Assign regular user permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '20000000-0000-0000-0000-000000000003', id FROM permissions
WHERE name IN ('user.read', 'user.update', 'biometric.enroll', 'biometric.verify')
ON CONFLICT DO NOTHING;

-- Assign SUPER_ADMIN role to system admin user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, '10000000-0000-0000-0000-000000000001'
FROM users u
WHERE u.email = 'admin@fivucsas.local'
ON CONFLICT DO NOTHING;
