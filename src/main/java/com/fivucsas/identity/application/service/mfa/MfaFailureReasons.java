package com.fivucsas.identity.application.service.mfa;

/**
 * The single definition of the MFA failure reasons written to the security audit log,
 * whether a step handler reports one through {@link MfaStepResult#fail(String)} or a
 * caller derives it from the submitted payload. They must name the real cause.
 */
public final class MfaFailureReasons {

    /** The verifier compared the probe against the enrolled template and found no match. */
    public static final String FACE_MISMATCH = "face_mismatch";
    /** The biometric processor flagged the capture as a presentation attack. */
    public static final String FACE_SPOOF_DETECTED = "face_spoof_detected";
    /** The biometric processor answered without a {@code verified} verdict (fail-closed). */
    public static final String FACE_VERIFIER_NO_VERDICT = "face_verifier_no_verdict";
    /** Neither a face image nor a usable embedding was submitted. */
    public static final String MISSING_FACE_IMAGE = "missing_face_image";
    /** Face verification failed and the handler did not report a specific cause. */
    public static final String FACE_VERIFICATION_FAILED = "face_verification_failed";

    /** The password did not match. */
    public static final String INVALID_PASSWORD = "invalid_password";
    /** No email or SMS one-time code was submitted. */
    public static final String MISSING_OTP_CODE = "missing_otp_code";
    /** The email or SMS one-time code was wrong or expired. */
    public static final String INVALID_OR_EXPIRED_OTP = "invalid_or_expired_otp";
    /** No authenticator-app code was submitted. */
    public static final String MISSING_TOTP_CODE = "missing_totp_code";
    /** The authenticator-app code was wrong. */
    public static final String INVALID_TOTP_CODE = "invalid_totp_code";
    /** No voice sample was submitted. */
    public static final String MISSING_VOICE_DATA = "missing_voice_data";
    /** The voice sample did not verify. */
    public static final String VOICE_VERIFICATION_FAILED = "voice_verification_failed";
    /** No WebAuthn assertion was submitted. */
    public static final String MISSING_WEBAUTHN_ASSERTION = "missing_webauthn_assertion";
    /** The WebAuthn assertion did not verify. */
    public static final String WEBAUTHN_VERIFICATION_FAILED = "webauthn_verification_failed";
    /** The legacy 2FA route cannot verify WebAuthn; callers must use the WebAuthn endpoints. */
    public static final String LEGACY_ROUTE_UNSUPPORTED_USE_WEBAUTHN_AUTHENTICATE = "legacy_route_unsupported_use_webauthn_authenticate";
    /** No QR token was submitted. */
    public static final String MISSING_QR_TOKEN = "missing_qr_token";
    /** The QR token was wrong or expired. */
    public static final String INVALID_QR_TOKEN = "invalid_qr_token";
    /** No NFC document data was submitted. */
    public static final String MISSING_NFC_DATA = "missing_nfc_data";
    /** The NFC card is unknown or belongs to another user. */
    public static final String NFC_CARD_NOT_FOUND_OR_NOT_OWNED = "nfc_card_not_found_or_not_owned";
    /** Any other method failed without a specific cause. */
    public static final String VERIFICATION_FAILED = "verification_failed";

    private MfaFailureReasons() {
    }
}
