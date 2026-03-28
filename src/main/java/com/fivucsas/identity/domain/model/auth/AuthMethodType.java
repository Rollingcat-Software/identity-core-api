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
    // Verification pipeline step types
    DOCUMENT_SCAN,
    NFC_CHIP_READ,
    DATA_EXTRACT,
    FACE_MATCH,
    LIVENESS_CHECK,
    ADDRESS_PROOF,
    WATCHLIST_CHECK,
    AGE_VERIFICATION,
    PHONE_VERIFICATION
}
