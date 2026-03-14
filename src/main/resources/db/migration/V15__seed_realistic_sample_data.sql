-- V15: Seed Realistic Sample Data
-- Adds tenants, users, roles, and audit logs for dashboard testing
-- All user passwords: Test@123 (BCrypt hash below)

-- BCrypt hash of 'Test@123' with work factor 10
-- $2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS

-- ============================================================================
-- 0. Ensure tenant schema has required columns (added after V1 in production)
-- ============================================================================

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS slug VARCHAR(100) UNIQUE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug) WHERE slug IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status) WHERE deleted_at IS NULL;

-- ============================================================================
-- 1. New Tenants
-- ============================================================================

INSERT INTO tenants (id, name, slug, domain, display_name, description, subscription_plan, is_active, max_users, max_biometric_enrollments, contact_email, contact_phone, status)
VALUES
    ('11111111-1111-1111-1111-111111111111',
     'Marmara University',
     'marmara-uni',
     'marmara.edu.tr',
     'Marmara University',
     'Marmara University Computer Engineering Department',
     'ENTERPRISE',
     TRUE,
     500,
     2000,
     'it@marmara.edu.tr',
     '+902162421500',
     'ACTIVE'),

    ('22222222-2222-2222-2222-222222222222',
     'TechCorp Istanbul',
     'techcorp-ist',
     'techcorp.com.tr',
     'TechCorp Istanbul',
     'Technology company based in Istanbul',
     'PREMIUM',
     TRUE,
     200,
     1000,
     'admin@techcorp.com.tr',
     '+902121234567',
     'ACTIVE'),

    ('33333333-3333-3333-3333-333333333333',
     'Anatolia Medical Center',
     'anatolia-med',
     'anatoliamed.com.tr',
     'Anatolia Medical Center',
     'Healthcare provider in central Anatolia',
     'BASIC',
     TRUE,
     50,
     250,
     'security@anatoliamed.com.tr',
     '+903121234567',
     'ACTIVE')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 2. Roles for New Tenants
-- ============================================================================

-- Marmara University roles
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active)
VALUES
    ('30000000-0000-0000-0001-000000000001', '11111111-1111-1111-1111-111111111111', 'TENANT_ADMIN', 'Tenant administrator', TRUE, TRUE),
    ('30000000-0000-0000-0001-000000000002', '11111111-1111-1111-1111-111111111111', 'USER', 'Regular user', TRUE, TRUE)
ON CONFLICT (tenant_id, name) DO NOTHING;

-- TechCorp Istanbul roles
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active)
VALUES
    ('30000000-0000-0000-0002-000000000001', '22222222-2222-2222-2222-222222222222', 'TENANT_ADMIN', 'Tenant administrator', TRUE, TRUE),
    ('30000000-0000-0000-0002-000000000002', '22222222-2222-2222-2222-222222222222', 'USER', 'Regular user', TRUE, TRUE)
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Anatolia Medical Center roles
INSERT INTO roles (id, tenant_id, name, description, is_system_role, is_active)
VALUES
    ('30000000-0000-0000-0003-000000000001', '33333333-3333-3333-3333-333333333333', 'TENANT_ADMIN', 'Tenant administrator', TRUE, TRUE),
    ('30000000-0000-0000-0003-000000000002', '33333333-3333-3333-3333-333333333333', 'USER', 'Regular user', TRUE, TRUE)
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Assign permissions to new tenant roles
-- TENANT_ADMIN roles get tenant admin permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'TENANT_ADMIN'
  AND r.tenant_id IN ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333')
  AND p.resource IN ('user', 'role', 'biometric', 'analytics', 'audit')
ON CONFLICT DO NOTHING;

-- USER roles get basic permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'USER'
  AND r.tenant_id IN ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333')
  AND p.name IN ('user.read', 'user.update', 'biometric.enroll', 'biometric.verify')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 3. New Users (password: Test@123)
-- ============================================================================

-- Marmara University users
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, email_verified, is_active, user_type, phone_number)
VALUES
    ('a1111111-0000-0000-0000-000000000001',
     '11111111-1111-1111-1111-111111111111',
     'ayse.demir@marmara.edu.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Ayse', 'Demir',
     TRUE, TRUE, 'TENANT_ADMIN', '+905301234501'),

    ('a1111111-0000-0000-0000-000000000002',
     '11111111-1111-1111-1111-111111111111',
     'mehmet.yilmaz@marmara.edu.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Mehmet', 'Yilmaz',
     TRUE, TRUE, 'TENANT_MEMBER', '+905301234502'),

    ('a1111111-0000-0000-0000-000000000003',
     '11111111-1111-1111-1111-111111111111',
     'elif.kaya@marmara.edu.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Elif', 'Kaya',
     TRUE, TRUE, 'TENANT_MEMBER', '+905301234503')
ON CONFLICT DO NOTHING;

-- TechCorp Istanbul users
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, email_verified, is_active, user_type, phone_number)
VALUES
    ('a2222222-0000-0000-0000-000000000001',
     '22222222-2222-2222-2222-222222222222',
     'can.ozturk@techcorp.com.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Can', 'Ozturk',
     TRUE, TRUE, 'TENANT_ADMIN', '+905301234504'),

    ('a2222222-0000-0000-0000-000000000002',
     '22222222-2222-2222-2222-222222222222',
     'zeynep.arslan@techcorp.com.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Zeynep', 'Arslan',
     TRUE, TRUE, 'TENANT_MEMBER', '+905301234505')
ON CONFLICT DO NOTHING;

-- Anatolia Medical Center users
INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, email_verified, is_active, user_type, phone_number)
VALUES
    ('a3333333-0000-0000-0000-000000000001',
     '33333333-3333-3333-3333-333333333333',
     'fatma.celik@anatoliamed.com.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Fatma', 'Celik',
     TRUE, TRUE, 'TENANT_ADMIN', '+905301234506'),

    ('a3333333-0000-0000-0000-000000000002',
     '33333333-3333-3333-3333-333333333333',
     'ahmet.sahin@anatoliamed.com.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Ahmet', 'Sahin',
     TRUE, TRUE, 'TENANT_MEMBER', '+905301234507'),

    ('a3333333-0000-0000-0000-000000000003',
     '33333333-3333-3333-3333-333333333333',
     'burak.koc@anatoliamed.com.tr',
     '$2a$10$nYHr0UVExd8a1AzvhZGXuuPlwoseNcDrLXctPbe7OpVsbHlKCVDpS',
     'Burak', 'Koc',
     FALSE, FALSE, 'TENANT_MEMBER', '+905301234508')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 4. Assign Roles to New Users
-- ============================================================================

-- Marmara Uni
INSERT INTO user_roles (user_id, role_id)
VALUES
    ('a1111111-0000-0000-0000-000000000001', '30000000-0000-0000-0001-000000000001'),
    ('a1111111-0000-0000-0000-000000000002', '30000000-0000-0000-0001-000000000002'),
    ('a1111111-0000-0000-0000-000000000003', '30000000-0000-0000-0001-000000000002')
ON CONFLICT DO NOTHING;

-- TechCorp
INSERT INTO user_roles (user_id, role_id)
VALUES
    ('a2222222-0000-0000-0000-000000000001', '30000000-0000-0000-0002-000000000001'),
    ('a2222222-0000-0000-0000-000000000002', '30000000-0000-0000-0002-000000000002')
ON CONFLICT DO NOTHING;

-- Anatolia Med
INSERT INTO user_roles (user_id, role_id)
VALUES
    ('a3333333-0000-0000-0000-000000000001', '30000000-0000-0000-0003-000000000001'),
    ('a3333333-0000-0000-0000-000000000002', '30000000-0000-0000-0003-000000000002'),
    ('a3333333-0000-0000-0000-000000000003', '30000000-0000-0000-0003-000000000002')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 5. Seed Audit Log Entries
-- ============================================================================

-- System admin login (current time - 7 days)
INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, success, ip_address, user_agent, created_at)
VALUES
    -- Admin logins over the past week
    ('00000000-0000-0000-0000-000000000000',
     (SELECT id FROM users WHERE email = 'admin@fivucsas.local'),
     'USER_LOGIN', 'AUTH', NULL, TRUE, '34.116.233.134', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '7 days'),

    ('00000000-0000-0000-0000-000000000000',
     (SELECT id FROM users WHERE email = 'admin@fivucsas.local'),
     'USER_LOGIN', 'AUTH', NULL, TRUE, '34.116.233.134', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '5 days'),

    ('00000000-0000-0000-0000-000000000000',
     (SELECT id FROM users WHERE email = 'admin@fivucsas.local'),
     'USER_LOGIN', 'AUTH', NULL, TRUE, '192.168.1.100', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '2 days'),

    -- Ayse Demir login
    ('11111111-1111-1111-1111-111111111111',
     'a1111111-0000-0000-0000-000000000001',
     'USER_LOGIN', 'AUTH', NULL, TRUE, '88.240.50.12', 'Mozilla/5.0 Firefox/121',
     CURRENT_TIMESTAMP - INTERVAL '6 days'),

    -- Mehmet failed login attempt
    ('11111111-1111-1111-1111-111111111111',
     'a1111111-0000-0000-0000-000000000002',
     'FAILED_LOGIN_ATTEMPT', 'AUTH', NULL, FALSE, '88.240.50.15', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '6 days 2 hours'),

    -- Mehmet successful login after
    ('11111111-1111-1111-1111-111111111111',
     'a1111111-0000-0000-0000-000000000002',
     'USER_LOGIN', 'AUTH', NULL, TRUE, '88.240.50.15', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '6 days 1 hour'),

    -- Can Ozturk login
    ('22222222-2222-2222-2222-222222222222',
     'a2222222-0000-0000-0000-000000000001',
     'USER_LOGIN', 'AUTH', NULL, TRUE, '176.42.10.100', 'Mozilla/5.0 Edge/120',
     CURRENT_TIMESTAMP - INTERVAL '4 days'),

    -- Fatma Celik login
    ('33333333-3333-3333-3333-333333333333',
     'a3333333-0000-0000-0000-000000000001',
     'USER_LOGIN', 'AUTH', NULL, TRUE, '5.44.80.22', 'Mozilla/5.0 Safari/17',
     CURRENT_TIMESTAMP - INTERVAL '3 days'),

    -- User creation events
    ('11111111-1111-1111-1111-111111111111',
     'a1111111-0000-0000-0000-000000000001',
     'USER_CREATED', 'USER', 'a1111111-0000-0000-0000-000000000002',
     TRUE, '88.240.50.12', 'Mozilla/5.0 Firefox/121',
     CURRENT_TIMESTAMP - INTERVAL '10 days'),

    ('11111111-1111-1111-1111-111111111111',
     'a1111111-0000-0000-0000-000000000001',
     'USER_CREATED', 'USER', 'a1111111-0000-0000-0000-000000000003',
     TRUE, '88.240.50.12', 'Mozilla/5.0 Firefox/121',
     CURRENT_TIMESTAMP - INTERVAL '10 days 1 hour'),

    ('22222222-2222-2222-2222-222222222222',
     'a2222222-0000-0000-0000-000000000001',
     'USER_CREATED', 'USER', 'a2222222-0000-0000-0000-000000000002',
     TRUE, '176.42.10.100', 'Mozilla/5.0 Edge/120',
     CURRENT_TIMESTAMP - INTERVAL '8 days'),

    -- Settings updated
    ('00000000-0000-0000-0000-000000000000',
     (SELECT id FROM users WHERE email = 'admin@fivucsas.local'),
     'SETTINGS_UPDATED', 'SETTINGS', NULL, TRUE, '34.116.233.134', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '9 days'),

    -- Failed login attempts (brute force simulation)
    ('22222222-2222-2222-2222-222222222222',
     NULL,
     'FAILED_LOGIN_ATTEMPT', 'AUTH', NULL, FALSE, '203.0.113.50', 'python-requests/2.31',
     CURRENT_TIMESTAMP - INTERVAL '4 days 3 hours'),

    ('22222222-2222-2222-2222-222222222222',
     NULL,
     'FAILED_LOGIN_ATTEMPT', 'AUTH', NULL, FALSE, '203.0.113.50', 'python-requests/2.31',
     CURRENT_TIMESTAMP - INTERVAL '4 days 3 hours 1 minute'),

    ('22222222-2222-2222-2222-222222222222',
     NULL,
     'FAILED_LOGIN_ATTEMPT', 'AUTH', NULL, FALSE, '203.0.113.50', 'python-requests/2.31',
     CURRENT_TIMESTAMP - INTERVAL '4 days 3 hours 2 minutes'),

    -- User updated
    ('33333333-3333-3333-3333-333333333333',
     'a3333333-0000-0000-0000-000000000001',
     'USER_UPDATED', 'USER', 'a3333333-0000-0000-0000-000000000003',
     TRUE, '5.44.80.22', 'Mozilla/5.0 Safari/17',
     CURRENT_TIMESTAMP - INTERVAL '1 day'),

    -- Recent admin login
    ('00000000-0000-0000-0000-000000000000',
     (SELECT id FROM users WHERE email = 'admin@fivucsas.local'),
     'USER_LOGIN', 'AUTH', NULL, TRUE, '192.168.1.100', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '1 hour'),

    -- Password reset
    ('11111111-1111-1111-1111-111111111111',
     'a1111111-0000-0000-0000-000000000002',
     'PASSWORD_RESET', 'USER', 'a1111111-0000-0000-0000-000000000002',
     TRUE, '88.240.50.15', 'Mozilla/5.0 Chrome/120',
     CURRENT_TIMESTAMP - INTERVAL '3 days');
