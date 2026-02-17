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
    HARDWARE_KEY
}
