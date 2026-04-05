-- V30: Adaptive Multi-Factor Authentication Engine
-- Supports N-step flows, CHOICE steps, and passwordless authentication.
-- Backward compatible: all existing flows remain SEQUENTIAL.

-- 1. Add step_type to auth_flow_steps
ALTER TABLE auth_flow_steps
    ADD COLUMN step_type VARCHAR(20) NOT NULL DEFAULT 'SEQUENTIAL';

ALTER TABLE auth_flow_steps
    ADD CONSTRAINT chk_step_type CHECK (step_type IN ('SEQUENTIAL', 'CHOICE'));

-- 2. Join table for CHOICE step alternative methods
CREATE TABLE auth_flow_step_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    step_id UUID NOT NULL REFERENCES auth_flow_steps(id) ON DELETE CASCADE,
    auth_method_id UUID NOT NULL REFERENCES auth_methods(id) ON DELETE CASCADE,
    display_order INTEGER NOT NULL DEFAULT 0,
    UNIQUE(step_id, auth_method_id)
);

CREATE INDEX idx_step_methods_step ON auth_flow_step_methods(step_id);
CREATE INDEX idx_step_methods_method ON auth_flow_step_methods(auth_method_id);

-- 3. User preferred 2FA method
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_2fa_method VARCHAR(30);

-- 4. Allow up to 5 steps per flow
ALTER TABLE auth_flow_steps DROP CONSTRAINT IF EXISTS chk_step_order;
ALTER TABLE auth_flow_steps
    ADD CONSTRAINT chk_step_order CHECK (step_order >= 1 AND step_order <= 5);

-- 5. MFA session table for step-by-step verification
CREATE TABLE mfa_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(128) NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    flow_id UUID NOT NULL REFERENCES auth_flows(id),
    current_step INTEGER NOT NULL DEFAULT 1,
    total_steps INTEGER NOT NULL,
    steps_data JSONB NOT NULL DEFAULT '[]',
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_mfa_session_token ON mfa_sessions(session_token);
CREATE INDEX idx_mfa_session_user ON mfa_sessions(user_id);
CREATE INDEX idx_mfa_session_expiry ON mfa_sessions(expires_at)
    WHERE completed_at IS NULL;

-- 6. Seed adaptive CHOICE flow for Marmara tenant
INSERT INTO auth_flows (id, tenant_id, name, description, flow_type, operation_type, is_default, is_active)
VALUES (
    'f0000002-0000-0000-0000-000000000001',
    '11111111-1111-1111-1111-111111111111',
    'Marmara Adaptive Login',
    'Password + user-selectable 2FA from all available methods',
    'AUTHENTICATION', 'APP_LOGIN', false, true
) ON CONFLICT (id) DO NOTHING;

-- Step 1: Password (SEQUENTIAL)
INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, step_type, is_required)
SELECT 'a0000010-0000-0000-0000-000000000001',
       'f0000002-0000-0000-0000-000000000001',
       id, 1, 'SEQUENTIAL', true
FROM auth_methods WHERE type = 'PASSWORD'
ON CONFLICT (id) DO NOTHING;

-- Step 2: CHOICE of 2FA methods
INSERT INTO auth_flow_steps (id, auth_flow_id, auth_method_id, step_order, step_type, is_required)
SELECT 'a0000010-0000-0000-0000-000000000002',
       'f0000002-0000-0000-0000-000000000001',
       id, 2, 'CHOICE', true
FROM auth_methods WHERE type = 'EMAIL_OTP'  -- fallback/primary
ON CONFLICT (id) DO NOTHING;

-- Populate CHOICE alternatives for step 2
INSERT INTO auth_flow_step_methods (step_id, auth_method_id, display_order)
SELECT 'a0000010-0000-0000-0000-000000000002', id,
       CASE type
         WHEN 'TOTP' THEN 1
         WHEN 'EMAIL_OTP' THEN 2
         WHEN 'FACE' THEN 3
         WHEN 'SMS_OTP' THEN 4
         WHEN 'FINGERPRINT' THEN 5
         WHEN 'HARDWARE_KEY' THEN 6
         WHEN 'VOICE' THEN 7
         WHEN 'QR_CODE' THEN 8
         WHEN 'NFC_DOCUMENT' THEN 9
       END
FROM auth_methods
WHERE type IN ('TOTP','EMAIL_OTP','FACE','SMS_OTP','FINGERPRINT','HARDWARE_KEY','VOICE','QR_CODE','NFC_DOCUMENT')
ON CONFLICT DO NOTHING;
