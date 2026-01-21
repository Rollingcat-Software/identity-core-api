-- V6: Create refresh_tokens table
-- Purpose: Store refresh tokens for secure token rotation and session management

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    token VARCHAR(500) NOT NULL UNIQUE,
    expiry_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),

    CONSTRAINT fk_refresh_token_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_expiry ON refresh_tokens(expiry_date);
CREATE INDEX idx_refresh_tokens_is_revoked ON refresh_tokens(is_revoked) WHERE is_revoked = FALSE;

-- Comments for documentation
COMMENT ON TABLE refresh_tokens IS 'Stores refresh tokens for JWT token rotation and session management';
COMMENT ON COLUMN refresh_tokens.token IS 'Unique refresh token string (UUID)';
COMMENT ON COLUMN refresh_tokens.expiry_date IS 'Token expiration timestamp (default: 7 days from creation)';
COMMENT ON COLUMN refresh_tokens.is_revoked IS 'Flag indicating if token has been revoked (logout or rotation)';
COMMENT ON COLUMN refresh_tokens.ip_address IS 'Client IP address when token was created';
COMMENT ON COLUMN refresh_tokens.user_agent IS 'Client user agent when token was created';
