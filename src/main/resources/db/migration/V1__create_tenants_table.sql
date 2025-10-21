-- V1: Create Tenants Table
-- Multi-tenant support for SaaS platform

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255) UNIQUE,
    display_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,

    -- Subscription information
    subscription_plan VARCHAR(50) DEFAULT 'FREE' NOT NULL,
    subscription_start_date TIMESTAMP,
    subscription_end_date TIMESTAMP,
    max_users INTEGER DEFAULT 100 NOT NULL,
    max_biometric_enrollments INTEGER DEFAULT 500 NOT NULL,

    -- Contact information
    contact_email VARCHAR(255),
    contact_phone VARCHAR(20),

    -- Address
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    country VARCHAR(100),
    postal_code VARCHAR(20),

    -- Metadata
    settings JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_tenants_name ON tenants(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_tenants_domain ON tenants(domain) WHERE deleted_at IS NULL AND domain IS NOT NULL;
CREATE INDEX idx_tenants_active ON tenants(is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_tenants_subscription_plan ON tenants(subscription_plan) WHERE deleted_at IS NULL;

-- Comments
COMMENT ON TABLE tenants IS 'Multi-tenant organizations using the FIVUCSAS platform';
COMMENT ON COLUMN tenants.subscription_plan IS 'FREE, BASIC, PREMIUM, ENTERPRISE';
COMMENT ON COLUMN tenants.settings IS 'Tenant-specific configuration settings';
COMMENT ON COLUMN tenants.metadata IS 'Additional tenant metadata';

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default system tenant
INSERT INTO tenants (id, name, domain, display_name, subscription_plan, is_active, max_users, max_biometric_enrollments)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'system',
    'system.fivucsas.local',
    'System Tenant',
    'ENTERPRISE',
    TRUE,
    999999,
    999999
) ON CONFLICT (id) DO NOTHING;
