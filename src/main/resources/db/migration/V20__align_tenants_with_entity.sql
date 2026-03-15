-- V20: Align tenants table with Tenant entity
-- Adds columns expected by the JPA entity that are missing from the database

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS slug VARCHAR(50);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS description VARCHAR(500);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS biometric_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS session_timeout_minutes INTEGER NOT NULL DEFAULT 30;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS refresh_token_validity_days INTEGER NOT NULL DEFAULT 7;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT false;

-- Populate slug from name (lowercase, replace spaces with hyphens)
UPDATE tenants SET slug = LOWER(REPLACE(name, ' ', '-')) WHERE slug IS NULL;

-- Make slug unique and not null after populating
ALTER TABLE tenants ALTER COLUMN slug SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_slug ON tenants(slug);

-- Make contact_email not null if it isn't already (entity requires it)
-- First set a default for any nulls
UPDATE tenants SET contact_email = name || '@localhost' WHERE contact_email IS NULL;
