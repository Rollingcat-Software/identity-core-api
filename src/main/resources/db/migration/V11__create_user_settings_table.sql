-- V11: Create User Settings Table
-- Stores per-user settings as JSONB for flexibility

CREATE TABLE IF NOT EXISTS user_settings
(
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL UNIQUE REFERENCES users (id) ON DELETE CASCADE,
    settings   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX idx_user_settings_user_id ON user_settings (user_id);

COMMENT ON TABLE user_settings IS 'Per-user application settings stored as JSONB';
