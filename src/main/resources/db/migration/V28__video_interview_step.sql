-- V28: Add VIDEO_INTERVIEW verification step type and PENDING_REVIEW status

-- ============================================================================
-- Extend verification_step_results status constraint to include PENDING_REVIEW
-- ============================================================================
ALTER TABLE verification_step_results DROP CONSTRAINT IF EXISTS chk_step_result_status;
ALTER TABLE verification_step_results ADD CONSTRAINT chk_step_result_status
    CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','FAILED','SKIPPED','PENDING_REVIEW'));

-- ============================================================================
-- Extend auth_methods type constraint to include VIDEO_INTERVIEW
-- ============================================================================
ALTER TABLE auth_methods DROP CONSTRAINT IF EXISTS chk_auth_method_type;
ALTER TABLE auth_methods ADD CONSTRAINT chk_auth_method_type
    CHECK (type IN (
        'PASSWORD','EMAIL_OTP','SMS_OTP','TOTP','QR_CODE','FACE','FINGERPRINT','VOICE','NFC_DOCUMENT','HARDWARE_KEY',
        'DOCUMENT_SCAN','NFC_CHIP_READ','DATA_EXTRACT','FACE_MATCH','LIVENESS_CHECK',
        'ADDRESS_PROOF','WATCHLIST_CHECK','AGE_VERIFICATION','PHONE_VERIFICATION',
        'VIDEO_INTERVIEW'
    ));

-- ============================================================================
-- Seed VIDEO_INTERVIEW auth method
-- ============================================================================
INSERT INTO auth_methods (type, name, description, category, platforms, requires_enrollment, is_active) VALUES
    ('VIDEO_INTERVIEW', 'Video Interview', 'Record a short video for manual admin review', 'PREMIUM', '{WEB,ANDROID,IOS,DESKTOP}', false, true)
ON CONFLICT (type) DO NOTHING;
