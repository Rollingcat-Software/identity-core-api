-- V10: Align tenants table with Tenant entity
-- Adds missing columns that the JPA entity expects

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS slug VARCHAR(50) UNIQUE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS description VARCHAR(500);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS biometric_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS session_timeout_minutes INTEGER NOT NULL DEFAULT 30;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS refresh_token_validity_days INTEGER NOT NULL DEFAULT 7;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT FALSE;

-- Populate slug from name for existing rows
UPDATE tenants SET slug = LOWER(REPLACE(name, ' ', '-')) WHERE slug IS NULL;

-- Update system tenant
UPDATE tenants SET status = 'ACTIVE', contact_email = 'system@fivucsas.local' WHERE name = 'system' AND contact_email IS NULL;
