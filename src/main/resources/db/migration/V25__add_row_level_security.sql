-- V25: Add Row-Level Security (RLS) for multi-tenant data isolation
-- This migration enables PostgreSQL RLS on all tenant-scoped tables.
-- Access is restricted based on the current tenant_id set via session variable.

-- ============================================================
-- 1. Enable RLS on tenant-scoped tables
-- ============================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_flow_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 2. Create helper function to get current tenant from session
-- ============================================================

CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant_id', true), '')::UUID;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================
-- 3. Create RLS policies
-- Each table gets:
--   - A SELECT policy (tenant isolation for reads)
--   - An ALL policy (tenant isolation for writes)
--   - A bypass when no tenant is set (for admin/migration operations)
-- ============================================================

-- users
CREATE POLICY users_tenant_isolation ON users
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY users_tenant_insert ON users
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- roles
CREATE POLICY roles_tenant_isolation ON roles
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY roles_tenant_insert ON roles
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- user_roles (tenant_id comes through the user relationship)
-- user_roles has user_id which links to users.tenant_id
CREATE POLICY user_roles_tenant_isolation ON user_roles
    USING (
        EXISTS (
            SELECT 1 FROM users u
            WHERE u.id = user_roles.user_id
            AND (u.tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
        )
        OR current_tenant_id() IS NULL
    );

CREATE POLICY user_roles_tenant_insert ON user_roles
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM users u
            WHERE u.id = user_roles.user_id
            AND (u.tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
        )
        OR current_tenant_id() IS NULL
    );

-- auth_flows
CREATE POLICY auth_flows_tenant_isolation ON auth_flows
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY auth_flows_tenant_insert ON auth_flows
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- auth_flow_steps (linked through auth_flow_id -> auth_flows.tenant_id)
CREATE POLICY auth_flow_steps_tenant_isolation ON auth_flow_steps
    USING (
        EXISTS (
            SELECT 1 FROM auth_flows af
            WHERE af.id = auth_flow_steps.auth_flow_id
            AND (af.tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
        )
        OR current_tenant_id() IS NULL
    );

CREATE POLICY auth_flow_steps_tenant_insert ON auth_flow_steps
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM auth_flows af
            WHERE af.id = auth_flow_steps.auth_flow_id
            AND (af.tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
        )
        OR current_tenant_id() IS NULL
    );

-- auth_sessions
CREATE POLICY auth_sessions_tenant_isolation ON auth_sessions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY auth_sessions_tenant_insert ON auth_sessions
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- user_devices
CREATE POLICY user_devices_tenant_isolation ON user_devices
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY user_devices_tenant_insert ON user_devices
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- user_enrollments
CREATE POLICY user_enrollments_tenant_isolation ON user_enrollments
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY user_enrollments_tenant_insert ON user_enrollments
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- audit_logs
CREATE POLICY audit_logs_tenant_isolation ON audit_logs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

CREATE POLICY audit_logs_tenant_insert ON audit_logs
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ============================================================
-- 4. IMPORTANT: The table owner (typically the application user)
--    bypasses RLS by default. Force RLS for the app user too.
-- ============================================================

-- Note: Execute these manually if the application user is different
-- from the table owner. Example:
-- ALTER TABLE users FORCE ROW LEVEL SECURITY;
-- ALTER TABLE roles FORCE ROW LEVEL SECURITY;
-- etc.

-- ============================================================
-- 5. Add comments for documentation
-- ============================================================

COMMENT ON POLICY users_tenant_isolation ON users IS 'RLS: Restrict user access to current tenant';
COMMENT ON POLICY roles_tenant_isolation ON roles IS 'RLS: Restrict role access to current tenant';
COMMENT ON POLICY auth_flows_tenant_isolation ON auth_flows IS 'RLS: Restrict auth flow access to current tenant';
COMMENT ON POLICY auth_sessions_tenant_isolation ON auth_sessions IS 'RLS: Restrict auth session access to current tenant';
COMMENT ON POLICY user_devices_tenant_isolation ON user_devices IS 'RLS: Restrict device access to current tenant';
COMMENT ON POLICY user_enrollments_tenant_isolation ON user_enrollments IS 'RLS: Restrict enrollment access to current tenant';
COMMENT ON POLICY audit_logs_tenant_isolation ON audit_logs IS 'RLS: Restrict audit log access to current tenant';
COMMENT ON FUNCTION current_tenant_id() IS 'Returns the current tenant ID from session variable app.current_tenant_id';
