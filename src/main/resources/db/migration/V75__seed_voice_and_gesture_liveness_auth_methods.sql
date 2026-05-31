-- V75: make VOICE + GESTURE_LIVENESS available as active LOGIN auth methods.
--
-- WHAT:
--   The dashboard auth-flow builder reads GET /api/v1/auth-methods to populate the
--   pool of selectable LOGIN methods. The frontend enum already knows VOICE and
--   GESTURE_LIVENESS, but the auth_methods DB table did NOT expose them as active:
--     * VOICE has been seeded since V16 but with is_active = FALSE (see V16's
--       seed row) and so was filtered out of the active list the API returns.
--     * GESTURE_LIVENESS was never seeded AND is not in the chk_auth_method_type
--       CHECK constraint, so it could not be inserted at all.
--   This migration activates VOICE and seeds GESTURE_LIVENESS so both are returned
--   as active methods, matching the frontend enum.
--
-- WHY:
--   Tenants building auth flows expect the full method set (VOICE biometric +
--   gesture-based liveness challenge) to be placeable as a Layer-1 / step factor.
--   Without these rows the builder silently omits two shipped capabilities.
--
-- SHAPE:
--   Mirrors the V73 auth_methods INSERT shape (incl. supports_usernameless). Both
--   VOICE and GESTURE_LIVENESS are FALSE for supports_usernameless: neither can
--   begin a login without an up-front identifier (you cannot resolve WHICH user's
--   voiceprint / liveness challenge to run from the factor alone — unlike a
--   discoverable PASSKEY or a device-confirmed QR scan).
--
-- ADDITIVE / REVERSIBLE-SAFE:
--   Idempotent (ON CONFLICT (type) DO NOTHING + guarded constraint swap + guarded
--   UPDATE). Widening a CHECK constraint and seeding rows is additive — safe to
--   leave applied if the image is rolled back. Applies cleanly from V74.

-- 1. Widen the type CHECK constraint to admit GESTURE_LIVENESS. The full list is
--    the most-recent/complete one (V73: the V28 verification-pipeline step types +
--    PASSKEY/APPROVE_LOGIN) PLUS GESTURE_LIVENESS — dropping any existing type
--    would violate rows already seeded by V16/V26/V28/V73.
DO $$ BEGIN
    ALTER TABLE auth_methods DROP CONSTRAINT IF EXISTS chk_auth_method_type;
    ALTER TABLE auth_methods ADD CONSTRAINT chk_auth_method_type
        CHECK (type IN (
            'PASSWORD','EMAIL_OTP','SMS_OTP','TOTP','QR_CODE','FACE','FINGERPRINT','VOICE','NFC_DOCUMENT','HARDWARE_KEY',
            'DOCUMENT_SCAN','NFC_CHIP_READ','DATA_EXTRACT','FACE_MATCH','LIVENESS_CHECK',
            'ADDRESS_PROOF','WATCHLIST_CHECK','AGE_VERIFICATION','PHONE_VERIFICATION',
            'VIDEO_INTERVIEW',
            'PASSKEY','APPROVE_LOGIN',
            'GESTURE_LIVENESS'
        ));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 2. Seed GESTURE_LIVENESS (and VOICE defensively, in case a fresh DB ever lacks
--    the V16 row). VOICE = PREMIUM biometric; GESTURE_LIVENESS = a PREMIUM liveness
--    challenge (blink/smile/head-turn). Both require enrollment-time setup and are
--    NOT usernameless. is_active = TRUE so the API returns them.
INSERT INTO auth_methods (type, name, description, category, platforms, requires_enrollment, supports_usernameless, is_active) VALUES
('VOICE',             'Voice Recognition',  'Biometric voice verification',                          'PREMIUM', '{WEB,ANDROID,IOS,DESKTOP}', true, false, true),
('GESTURE_LIVENESS',  'Gesture Liveness',   'Active liveness challenge (blink / smile / head turn)', 'PREMIUM', '{WEB,ANDROID,IOS,DESKTOP}', true, false, true)
ON CONFLICT (type) DO NOTHING;

-- 3. If VOICE already exists from the V16 seed but is still inactive, activate it
--    (the ON CONFLICT above does not touch the existing row's is_active).
UPDATE auth_methods SET is_active = true WHERE type = 'VOICE' AND is_active = false;
