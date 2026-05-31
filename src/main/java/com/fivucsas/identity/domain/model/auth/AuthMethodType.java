package com.fivucsas.identity.domain.model.auth;

public enum AuthMethodType {
    PASSWORD,
    EMAIL_OTP,
    SMS_OTP,
    TOTP,
    QR_CODE,
    FACE,
    FINGERPRINT,
    VOICE,
    NFC_DOCUMENT,
    HARDWARE_KEY,
    // Usernameless / cross-device Layer-1 methods (config-driven login engine).
    // PASSKEY is the discoverable mode of WebAuthn; APPROVE_LOGIN is the
    // number-matching mode of the QR cross-device-approval method (task #16 G).
    PASSKEY,
    APPROVE_LOGIN,
    // Active liveness challenge (blink / smile / head turn). Seeded as an active
    // auth_methods row by V75 so the dashboard auth-flow builder can offer it
    // alongside VOICE; not usernameless (cannot resolve the user from the factor
    // alone). The @Enumerated(EnumType.STRING) AuthMethod.type mapping REQUIRES
    // this constant to exist or loading the V75-seeded row would throw.
    GESTURE_LIVENESS,
    // Verification pipeline step types
    DOCUMENT_SCAN,
    NFC_CHIP_READ,
    DATA_EXTRACT,
    FACE_MATCH,
    LIVENESS_CHECK,
    ADDRESS_PROOF,
    WATCHLIST_CHECK,
    AGE_VERIFICATION,
    PHONE_VERIFICATION,
    VIDEO_INTERVIEW
}
