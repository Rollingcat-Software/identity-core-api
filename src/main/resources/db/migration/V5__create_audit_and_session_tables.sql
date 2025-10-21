-- V5: Create Audit Logs and Session Tables
-- Comprehensive audit trail and session management

-- Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Action details
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,

    -- HTTP request details
    http_method VARCHAR(10),
    endpoint VARCHAR(500),
    status_code INTEGER,

    -- Change tracking
    old_values JSONB,
    new_values JSONB,

    -- Result
    success BOOLEAN NOT NULL,
    error_message TEXT,

    -- Client information
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_id VARCHAR(100),
    location JSONB,  -- City, country, coordinates, etc.

    -- Performance
    response_time_ms INTEGER,

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamp
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Refresh Tokens Table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Token
    token_hash VARCHAR(255) NOT NULL UNIQUE,

    -- Device information
    device_id VARCHAR(100),
    device_name VARCHAR(100),
    device_type VARCHAR(50),  -- 'MOBILE', 'WEB', 'DESKTOP'

    -- Client information
    ip_address VARCHAR(45),
    user_agent TEXT,

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE NOT NULL,
    revoked_at TIMESTAMP,
    revoked_reason VARCHAR(255),

    -- Expiration
    expires_at TIMESTAMP NOT NULL,

    -- Usage tracking
    last_used_at TIMESTAMP,
    usage_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Active Sessions Table
CREATE TABLE IF NOT EXISTS active_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Session token (hash of JWT)
    session_token_hash VARCHAR(255) NOT NULL UNIQUE,

    -- Device information
    device_id VARCHAR(100),
    device_name VARCHAR(100),
    device_type VARCHAR(50),

    -- Client information
    ip_address VARCHAR(45),
    user_agent TEXT,
    location JSONB,

    -- Status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,

    -- Activity tracking
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Expiration
    expires_at TIMESTAMP NOT NULL,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Password History Table (for password reuse prevention)
CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Security Events Table
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Event details
    event_type VARCHAR(100) NOT NULL,  -- 'LOGIN_FAILED', 'ACCOUNT_LOCKED', 'SUSPICIOUS_ACTIVITY', etc.
    severity VARCHAR(20) NOT NULL,  -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description TEXT NOT NULL,

    -- Context
    ip_address VARCHAR(45),
    user_agent TEXT,
    location JSONB,

    -- Action taken
    action_taken VARCHAR(255),
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    resolved_by UUID REFERENCES users(id),

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamp
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Indexes
-- Audit logs
CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_success ON audit_logs(success);

-- Refresh tokens
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_tenant ON refresh_tokens(tenant_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_active ON refresh_tokens(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- Active sessions
CREATE INDEX idx_sessions_user ON active_sessions(user_id);
CREATE INDEX idx_sessions_tenant ON active_sessions(tenant_id);
CREATE INDEX idx_sessions_active ON active_sessions(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_sessions_last_activity ON active_sessions(last_activity_at DESC);

-- Password history
CREATE INDEX idx_password_history_user ON password_history(user_id);
CREATE INDEX idx_password_history_created ON password_history(created_at DESC);

-- Security events
CREATE INDEX idx_security_events_tenant ON security_events(tenant_id);
CREATE INDEX idx_security_events_user ON security_events(user_id);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_created ON security_events(created_at DESC);
CREATE INDEX idx_security_events_resolved ON security_events(resolved) WHERE resolved = FALSE;

-- Comments
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail of all system actions';
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for maintaining user sessions';
COMMENT ON TABLE active_sessions IS 'Currently active user sessions';
COMMENT ON TABLE password_history IS 'Historical passwords to prevent reuse';
COMMENT ON TABLE security_events IS 'Security-related events and incidents';

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    -- Delete expired sessions
    DELETE FROM active_sessions WHERE expires_at < CURRENT_TIMESTAMP;

    -- Delete expired refresh tokens
    UPDATE refresh_tokens
    SET is_active = FALSE, is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP, revoked_reason = 'EXPIRED'
    WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old audit logs (retain for 1 year)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM audit_logs
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 year';
END;
$$ LANGUAGE plpgsql;
