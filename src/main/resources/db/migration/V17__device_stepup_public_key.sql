-- V17: Add device public key for fingerprint step-up authentication (ECDSA P-256)
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS public_key TEXT;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS public_key_algorithm VARCHAR(20) DEFAULT 'EC_P256';
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS step_up_registered_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_user_devices_stepup ON user_devices(user_id) WHERE public_key IS NOT NULL;
