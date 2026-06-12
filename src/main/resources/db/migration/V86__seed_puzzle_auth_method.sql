-- V86: seed the PUZZLE auth method (sub-project B, Phase 1).
--
-- PUZZLE proves liveness by re-scoring randomised challenge traces server-side.
-- Identity comes from an embedding match (later phases). It is a selectable
-- LOGIN factor, NOT a verification-pipeline step type — compare GESTURE_LIVENESS
-- which is a FACE anti-spoof sub-component and deliberately has no auth_methods
-- row and no standalone handler.
--
-- This migration:
--   1. Widens chk_auth_method_type on auth_methods to admit 'PUZZLE'.
--   2. Widens chk_enrollment_method on user_enrollments to admit 'PUZZLE'
--      (mirrors V83 which did the same for APPROVE_LOGIN + PASSKEY; omitting
--      this sibling constraint would let auto-enrollment silently fail the
--      check as happened with V73/V83).
--   3. Seeds the PUZZLE auth_methods row with ON CONFLICT DO NOTHING.
--
-- Additive + reversible: the row can be deactivated (is_active=false) or the
-- flag app.auth.puzzle-layer can be set back to false without a migration rollback.
-- No auth_flow_steps schema change — layer config rides the existing config JSONB.
--
-- Idempotent: IF NOT EXISTS / ON CONFLICT DO NOTHING / guarded constraint swap.

-- 1. Widen chk_auth_method_type to include PUZZLE.
--    Full list = V73 set + PUZZLE. Verification-pipeline step types are
--    intentionally absent (they have no auth_methods rows).
DO $$ BEGIN
    ALTER TABLE auth_methods DROP CONSTRAINT IF EXISTS chk_auth_method_type;
    ALTER TABLE auth_methods ADD CONSTRAINT chk_auth_method_type
        CHECK (type IN (
            'PASSWORD','EMAIL_OTP','SMS_OTP','TOTP','QR_CODE','FACE','FINGERPRINT','VOICE','NFC_DOCUMENT','HARDWARE_KEY',
            'DOCUMENT_SCAN','NFC_CHIP_READ','DATA_EXTRACT','FACE_MATCH','LIVENESS_CHECK',
            'ADDRESS_PROOF','WATCHLIST_CHECK','AGE_VERIFICATION','PHONE_VERIFICATION',
            'VIDEO_INTERVIEW',
            'PASSKEY','APPROVE_LOGIN',
            'PUZZLE'
        ));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 2. Widen chk_enrollment_method on user_enrollments to include PUZZLE.
--    Full list = V83 set + PUZZLE (mirrors the V83 drop-and-re-add pattern).
ALTER TABLE user_enrollments DROP CONSTRAINT IF EXISTS chk_enrollment_method;
ALTER TABLE user_enrollments ADD CONSTRAINT chk_enrollment_method
    CHECK (auth_method_type::text = ANY (ARRAY[
        'PASSWORD'::varchar, 'EMAIL_OTP'::varchar, 'SMS_OTP'::varchar,
        'TOTP'::varchar, 'QR_CODE'::varchar, 'FACE'::varchar,
        'FINGERPRINT'::varchar, 'VOICE'::varchar, 'NFC_DOCUMENT'::varchar,
        'HARDWARE_KEY'::varchar, 'APPROVE_LOGIN'::varchar, 'PASSKEY'::varchar,
        'PUZZLE'::varchar
    ]::text[]));

-- 3. Seed the PUZZLE auth_methods row.
--    requires_enrollment=true: a PUZZLE step requires a prior challenge
--    registration (the puzzle geometry is personalised).
--    supports_usernameless=false: PUZZLE does not identify the user; identity
--    comes from the embedding match in the same or a sibling step.
INSERT INTO auth_methods (type, name, description, category, platforms, requires_enrollment, supports_usernameless, is_active) VALUES
('PUZZLE', 'Puzzle', 'Server-scored liveness challenge: randomised trace proves a live person is present', 'PREMIUM', '{WEB,ANDROID,IOS,DESKTOP}', true, false, true)
ON CONFLICT (type) DO NOTHING;
