package com.fivucsas.identity.infrastructure.email;

/**
 * What a one-time code is being sent for. Drives the subject line and body
 * wording of the branded OTP email so the recipient sees an accurate label
 * (e.g. a password-reset code is never presented as a generic "verification
 * code").
 */
public enum OtpPurpose {

    /** A login / 2FA email-OTP step ("verification code"). */
    LOGIN_VERIFICATION,

    /** Confirming a newly registered account's email address. */
    EMAIL_VERIFICATION,

    /** Proving control of an email when linking it to an existing identity. */
    ACCOUNT_LINK,

    /** Resetting a forgotten password ("password reset code"). */
    PASSWORD_RESET
}
