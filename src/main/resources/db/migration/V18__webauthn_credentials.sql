-- WebAuthn credential storage for FIDO2/passkey authentication
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   VARCHAR(512) NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,
    public_key_algorithm VARCHAR(20) NOT NULL DEFAULT 'ES256',
    sign_count      BIGINT NOT NULL DEFAULT 0,
    device_name     VARCHAR(100),
    attestation_format VARCHAR(50),
    transports      VARCHAR(255),
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);
