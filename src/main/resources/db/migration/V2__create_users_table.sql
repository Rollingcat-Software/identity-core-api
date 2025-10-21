-- V2: Create Users Table
-- User authentication and profile management

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Authentication
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE NOT NULL,
    email_verification_token VARCHAR(255),
    email_verification_sent_at TIMESTAMP,

    -- Password reset
    password_reset_token VARCHAR(255),
    password_reset_sent_at TIMESTAMP,
    password_reset_expires_at TIMESTAMP,
    password_changed_at TIMESTAMP,

    -- User profile
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    middle_name VARCHAR(100),
    phone_number VARCHAR(20),
    phone_verified BOOLEAN DEFAULT FALSE,
    date_of_birth DATE,
    gender VARCHAR(20),

    -- Profile picture
    profile_picture_url VARCHAR(500),

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_locked BOOLEAN DEFAULT FALSE NOT NULL,
    locked_until TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0 NOT NULL,

    -- Login tracking
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    last_activity_at TIMESTAMP,

    -- Preferences
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    preferences JSONB DEFAULT '{}',

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,

    -- Constraints
    CONSTRAINT unique_tenant_email UNIQUE (tenant_id, email),
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'),
    CONSTRAINT valid_phone CHECK (phone_number IS NULL OR phone_number ~* '^\+?[1-9]\d{1,14}$')
);

-- Indexes
CREATE INDEX idx_users_tenant_id ON users(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_tenant_email ON users(tenant_id, email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_active ON users(is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token) WHERE email_verification_token IS NOT NULL;
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;
CREATE INDEX idx_users_phone ON users(phone_number) WHERE deleted_at IS NULL AND phone_number IS NOT NULL;

-- Comments
COMMENT ON TABLE users IS 'Platform users with authentication credentials';
COMMENT ON COLUMN users.password_hash IS 'BCrypt hashed password';
COMMENT ON COLUMN users.failed_login_attempts IS 'Counter for brute force protection';
COMMENT ON COLUMN users.is_locked IS 'Account locked due to security reasons';

-- Trigger
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create admin user for system tenant (password: Admin@123)
INSERT INTO users (
    tenant_id,
    email,
    password_hash,
    first_name,
    last_name,
    email_verified,
    is_active
)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'admin@fivucsas.local',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzQzf5v8zS',  -- BCrypt hash of 'Admin@123'
    'System',
    'Administrator',
    TRUE,
    TRUE
) ON CONFLICT DO NOTHING;
