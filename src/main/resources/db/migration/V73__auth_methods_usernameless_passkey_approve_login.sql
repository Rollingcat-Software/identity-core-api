-- V73: config-driven login engine — usernameless / cross-device auth methods.
--
-- Task #16 (A + G):
--   * Add the supports_usernameless flag to auth_methods. It is TRUE for any
--     method that can begin a login with NO up-front identifier (email/username)
--     because the user is resolved FROM the factor:
--       - PASSKEY        (discoverable / resident-key WebAuthn)
--       - APPROVE_LOGIN  (number-matching cross-device approval)
--       - QR_CODE        (scan-to-approve cross-device approval)
--     HARDWARE_KEY stays FALSE here: a plain (non-discoverable) FIDO2 key needs
--     an allowCredentials hint, so it is usernameless ONLY when registered as a
--     discoverable resident key — that is tracked per-credential
--     (webauthn_credentials.discoverable, V72), not per-method.
--
--   * Seed the two new method rows (PASSKEY, APPROVE_LOGIN). Per task #16 G these
--     are the discoverable mode of WebAuthn and the number-matching mode of the
--     QR cross-device-approval method respectively; they are modelled as their
--     own AuthMethodType rows so a tenant can place them as a Layer-1 step.
--
--   * Widen the chk_auth_method_type CHECK constraint to admit the two new
--     types. The verification-pipeline step types (DOCUMENT_SCAN, etc.) are
--     NOT auth_methods rows so they are intentionally absent here.
--
-- Idempotent (IF NOT EXISTS / ON CONFLICT DO NOTHING / guarded constraint swap)
-- to match the V16 convention.

-- 1. supports_usernameless column (defaults false → existing rows unchanged).
ALTER TABLE auth_methods
    ADD COLUMN IF NOT EXISTS supports_usernameless BOOLEAN NOT NULL DEFAULT false;

-- 2. Widen the type CHECK constraint to admit PASSKEY + APPROVE_LOGIN. The
--    full list mirrors V28 (which added the verification-pipeline step types to
--    auth_methods) + the two new login methods — dropping any existing type
--    would violate rows already seeded by V16/V26/V28.
DO $$ BEGIN
    ALTER TABLE auth_methods DROP CONSTRAINT IF EXISTS chk_auth_method_type;
    ALTER TABLE auth_methods ADD CONSTRAINT chk_auth_method_type
        CHECK (type IN (
            'PASSWORD','EMAIL_OTP','SMS_OTP','TOTP','QR_CODE','FACE','FINGERPRINT','VOICE','NFC_DOCUMENT','HARDWARE_KEY',
            'DOCUMENT_SCAN','NFC_CHIP_READ','DATA_EXTRACT','FACE_MATCH','LIVENESS_CHECK',
            'ADDRESS_PROOF','WATCHLIST_CHECK','AGE_VERIFICATION','PHONE_VERIFICATION',
            'VIDEO_INTERVIEW',
            'PASSKEY','APPROVE_LOGIN'
        ));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 3. Seed the two new methods. PASSKEY is the discoverable WebAuthn mode;
--    APPROVE_LOGIN is the number-matching cross-device approval mode. Both are
--    usernameless. PASSKEY requires a prior passkey registration (an enrolled
--    discoverable credential); APPROVE_LOGIN requires a registered device with a
--    push token, so both carry requires_enrollment=true — the engine's
--    usernameless dead-end exemption (task #16 F) covers the Layer-1 case where
--    the factor itself proves enrollment.
INSERT INTO auth_methods (type, name, description, category, platforms, requires_enrollment, supports_usernameless, is_active) VALUES
('PASSKEY',       'Passkey',         'Usernameless discoverable WebAuthn passkey',     'PREMIUM',    '{WEB,ANDROID,IOS,DESKTOP}', true, true, true),
('APPROVE_LOGIN', 'Approve Login',   'Cross-device number-matching login approval',    'STANDARD',   '{WEB,ANDROID,IOS,DESKTOP}', true, true, true)
ON CONFLICT (type) DO NOTHING;

-- 4. Flag the existing usernameless-capable methods. QR_CODE is cross-device
--    scan-to-approve. (PASSKEY / APPROVE_LOGIN are seeded TRUE above.)
UPDATE auth_methods SET supports_usernameless = true WHERE type = 'QR_CODE';
