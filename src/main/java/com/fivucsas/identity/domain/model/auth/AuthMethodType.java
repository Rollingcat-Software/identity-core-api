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
    // PUZZLE liveness layer (sub-project B). A PUZZLE step proves liveness by
    // re-scoring randomised challenge traces server-side; identity is provided
    // by an embedding match (sub-project C). PUZZLE is a selectable LOGIN factor
    // (unlike GESTURE_LIVENESS, which is a FACE sub-component and is never
    // selectable). It is surfaced ONLY when PuzzleLayerPolicy is enabled —
    // the ManageAuthMethodService filters it out of the catalog when the policy
    // is OFF, so this enum value is present but invisible by default.
    PUZZLE,
    // Verification pipeline step types — NOT login factors. These must never
    // appear in the /auth-methods catalog or the auth-flow builder.
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
     * <p>PUZZLE is included here (it IS a login factor, not a pipeline step), but
     * it is additionally gated by {@code PuzzleLayerPolicy}: when that policy is
     * OFF the service layer filters PUZZLE out of every catalog response, so the
     * set membership here is a necessary but not sufficient condition for a type
     * to appear in the API. GESTURE_LIVENESS is deliberately absent from this set
     * and has no auth_methods row — it is an active-liveness sub-component of FACE.
     *
     * <p>Keep this list in lockstep with the documented login methods
     * (api CLAUDE.md V73-V75, V86) and the web {@code LOGIN_METHOD_TYPES} allow-list.
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
            APPROVE_LOGIN,
            PUZZLE
    );

    /**
     * True when this type is a login method (a factor usable to authenticate),
     * as opposed to a verification-pipeline step type. Drives the tenant
     * Auth-Methods list filter and the login-time enforcement gate.
     *
     * <p>Note: {@code PUZZLE} returns true here but is additionally gated by
     * {@code PuzzleLayerPolicy}. When that policy is OFF the service layer
     * suppresses PUZZLE from every catalog response.
     */
    public boolean isLoginMethod() {
        return LOGIN_METHODS.contains(this);
    }
}
