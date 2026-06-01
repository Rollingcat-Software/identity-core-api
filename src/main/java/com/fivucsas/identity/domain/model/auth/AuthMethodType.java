package com.fivucsas.identity.domain.model.auth;

import java.util.EnumSet;
import java.util.Set;

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
    VIDEO_INTERVIEW;

    /**
     * The canonical set of <em>login</em> methods — factors a user can present
     * to sign in (the tenant Auth-Methods toggles + the auth-flow builder are
     * scoped to these). Everything NOT in this set is a verification-pipeline
     * step type (DOCUMENT_SCAN, FACE_MATCH, LIVENESS_CHECK, …) or a sub-component
     * of another factor (GESTURE_LIVENESS — not modelled here — is a FACE
     * liveness sub-component, never a standalone login factor), and must never be
     * offered as a selectable login method.
     *
     * <p>Keep this list in lockstep with the documented login methods
     * (api CLAUDE.md V73-V75) and the web {@code LOGIN_METHOD_TYPES} allow-list.
     */
    private static final Set<AuthMethodType> LOGIN_METHODS = EnumSet.of(
            PASSWORD,
            EMAIL_OTP,
            SMS_OTP,
            TOTP,
            FACE,
            FINGERPRINT,
            VOICE,
            NFC_DOCUMENT,
            HARDWARE_KEY,
            QR_CODE,
            PASSKEY,
            APPROVE_LOGIN
    );

    /**
     * True when this type is a login method (a factor usable to authenticate),
     * as opposed to a verification-pipeline step type. Drives the tenant
     * Auth-Methods list filter and the login-time enforcement gate.
     */
    public boolean isLoginMethod() {
        return LOGIN_METHODS.contains(this);
    }
}
