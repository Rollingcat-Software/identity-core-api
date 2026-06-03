-- V83: widen chk_enrollment_method to include APPROVE_LOGIN + PASSKEY.
--
-- V73 added the APPROVE_LOGIN + PASSKEY AuthMethodType enum values and widened
-- chk_auth_method_type, but MISSED this sibling constraint on user_enrollments.
-- As a result the device-implicit auto-enrollment
-- (ManageEnrollmentService.ensureAutoBoundEnrollment /
--  UsernamelessLoginFlowService.ensureApproveLoginEnrollment) INSERT silently
-- failed its check ("violates check constraint chk_enrollment_method") and was
-- swallowed — so APPROVE_LOGIN could never be enrolled and the auth-methods UI
-- showed it permanently "not set up / on your device".
--
-- Idempotent: drop + re-add with the full method set (mirrors the existing
-- cast-to-text/ANY(ARRAY ...) form). Additive + reversible (re-drop to revert).
ALTER TABLE user_enrollments DROP CONSTRAINT IF EXISTS chk_enrollment_method;
ALTER TABLE user_enrollments ADD CONSTRAINT chk_enrollment_method
    CHECK (auth_method_type::text = ANY (ARRAY[
        'PASSWORD'::varchar, 'EMAIL_OTP'::varchar, 'SMS_OTP'::varchar,
        'TOTP'::varchar, 'QR_CODE'::varchar, 'FACE'::varchar,
        'FINGERPRINT'::varchar, 'VOICE'::varchar, 'NFC_DOCUMENT'::varchar,
        'HARDWARE_KEY'::varchar, 'APPROVE_LOGIN'::varchar, 'PASSKEY'::varchar
    ]::text[]));
