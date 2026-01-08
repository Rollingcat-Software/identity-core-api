-- Seed data for development environment
-- This file runs after Hibernate creates the schema (defer-datasource-initialization: true)

-- Insert default tenant
INSERT INTO tenants (id, name, slug, description, contact_email, contact_phone, status, max_users, biometric_enabled, session_timeout_minutes, refresh_token_validity_days, mfa_required, created_at, updated_at)
SELECT '00000000-0000-0000-0000-000000000001', 'FIVUCSAS', 'fivucsas', 'Default development tenant', 'admin@fivucsas.local', '+1234567890', 'ACTIVE', 1000, true, 30, 7, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id = '00000000-0000-0000-0000-000000000001');

-- Insert permissions (no created_at/updated_at columns in Permission entity)
INSERT INTO permissions (id, name, resource, action, description) VALUES
    ('00000000-0000-0000-0001-000000000001', 'user:create', 'user', 'create', 'Create users'),
    ('00000000-0000-0000-0001-000000000002', 'user:read', 'user', 'read', 'Read user data'),
    ('00000000-0000-0000-0001-000000000003', 'user:update', 'user', 'update', 'Update users'),
    ('00000000-0000-0000-0001-000000000004', 'user:delete', 'user', 'delete', 'Delete users'),
    ('00000000-0000-0000-0001-000000000005', 'biometric:enroll', 'biometric', 'enroll', 'Enroll biometric data'),
    ('00000000-0000-0000-0001-000000000006', 'biometric:verify', 'biometric', 'verify', 'Verify biometric data'),
    ('00000000-0000-0000-0001-000000000007', 'role:create', 'role', 'create', 'Create roles'),
    ('00000000-0000-0000-0001-000000000008', 'role:read', 'role', 'read', 'Read roles'),
    ('00000000-0000-0000-0001-000000000009', 'role:update', 'role', 'update', 'Update roles'),
    ('00000000-0000-0000-0001-000000000010', 'role:delete', 'role', 'delete', 'Delete roles'),
    ('00000000-0000-0000-0001-000000000011', 'analytics:view', 'analytics', 'view', 'View analytics'),
    ('00000000-0000-0000-0001-000000000012', 'audit:read', 'audit', 'read', 'Read audit logs');

-- Insert roles
INSERT INTO roles (id, name, description, is_system_role, is_active, tenant_id, created_at, updated_at) VALUES
    ('00000000-0000-0000-0002-000000000001', 'SUPER_ADMIN', 'Super administrator with all permissions', true, true, '00000000-0000-0000-0000-000000000001', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('00000000-0000-0000-0002-000000000002', 'ADMIN', 'Administrator with most permissions', true, true, '00000000-0000-0000-0000-000000000001', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    ('00000000-0000-0000-0002-000000000003', 'USER', 'Regular user', true, true, '00000000-0000-0000-0000-000000000001', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Assign all permissions to SUPER_ADMIN role
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000001'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000002'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000003'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000004'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000005'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000006'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000007'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000008'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000009'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000010'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000011'),
    ('00000000-0000-0000-0002-000000000001', '00000000-0000-0000-0001-000000000012');

-- Assign user permissions to USER role (only self-service permissions)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0002-000000000003', '00000000-0000-0000-0001-000000000002'),
    ('00000000-0000-0000-0002-000000000003', '00000000-0000-0000-0001-000000000005'),
    ('00000000-0000-0000-0002-000000000003', '00000000-0000-0000-0001-000000000006');

-- Insert admin user (password: Admin123!)
-- BCrypt hash of 'Admin123!'
INSERT INTO users (id, email, password_hash, first_name, last_name, status, tenant_id, is_biometric_enrolled, verification_count, created_at, updated_at) VALUES
    ('00000000-0000-0000-0003-000000000001', 'admin@fivucsas.local', '$2a$10$2ROySTPQpsemBFbomt0c3eKq8Y1BCeoVAHvLgzkZtzjochjsPdA3u', 'Admin', 'User', 'ACTIVE', '00000000-0000-0000-0000-000000000001', false, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Insert regular test user (password: User123!)
INSERT INTO users (id, email, password_hash, first_name, last_name, status, tenant_id, is_biometric_enrolled, verification_count, created_at, updated_at) VALUES
    ('00000000-0000-0000-0003-000000000002', 'user@fivucsas.local', '$2a$10$mggLk8Vt0ldp5vFoLl1rGe6hqGsXFADiK2N7qvzihZ2lR1U3e2RWm', 'Test', 'User', 'ACTIVE', '00000000-0000-0000-0000-000000000001', false, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Assign SUPER_ADMIN role to admin user
INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES
    ('00000000-0000-0000-0003-000000000001', '00000000-0000-0000-0002-000000000001', CURRENT_TIMESTAMP);

-- Assign USER role to test user
INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES
    ('00000000-0000-0000-0003-000000000002', '00000000-0000-0000-0002-000000000003', CURRENT_TIMESTAMP);
