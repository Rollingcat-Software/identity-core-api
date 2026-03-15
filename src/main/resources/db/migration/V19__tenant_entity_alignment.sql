-- V19: Align tenants table with Tenant JPA entity
-- Adds columns expected by the entity but missing from V1 schema

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS biometric_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS session_timeout_minutes  INTEGER NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS refresh_token_validity_days INTEGER NOT NULL DEFAULT 7,
    ADD COLUMN IF NOT EXISTS mfa_required             BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN tenants.biometric_enabled IS 'Whether biometric authentication is enabled for this tenant';
COMMENT ON COLUMN tenants.session_timeout_minutes IS 'Session timeout in minutes (default 30)';
COMMENT ON COLUMN tenants.refresh_token_validity_days IS 'Refresh token validity in days (default 7)';
COMMENT ON COLUMN tenants.mfa_required IS 'Whether MFA is required for all users in this tenant';
