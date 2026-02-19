-- V13: Add biometric step-up device and challenge tables

CREATE TABLE IF NOT EXISTS auth_biometric_device (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    key_id VARCHAR(128) NOT NULL,
    platform VARCHAR(32) NOT NULL,
    public_key_jwk TEXT NOT NULL,
    device_label VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_auth_biometric_device_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_biometric_device_user_key
    ON auth_biometric_device(user_id, key_id);

CREATE INDEX IF NOT EXISTS idx_auth_biometric_device_user
    ON auth_biometric_device(user_id)
    WHERE is_active = TRUE;

CREATE TABLE IF NOT EXISTS auth_biometric_challenge (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    challenge_id UUID NOT NULL UNIQUE,
    user_id UUID NOT NULL,
    nonce_base64 VARCHAR(512) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_auth_biometric_challenge_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_biometric_challenge_user
    ON auth_biometric_challenge(user_id);

CREATE INDEX IF NOT EXISTS idx_auth_biometric_challenge_expires
    ON auth_biometric_challenge(expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_biometric_challenge_used
    ON auth_biometric_challenge(used_at);

CREATE TRIGGER update_auth_biometric_device_updated_at
    BEFORE UPDATE ON auth_biometric_device
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE auth_biometric_device IS 'Registered user biometric device public keys for step-up authentication';
COMMENT ON TABLE auth_biometric_challenge IS 'One-time biometric step-up challenges signed by registered device keys';
