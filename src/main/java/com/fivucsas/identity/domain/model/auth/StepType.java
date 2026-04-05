package com.fivucsas.identity.domain.model.auth;

/**
 * Defines how an authentication flow step resolves its method.
 *
 * SEQUENTIAL: One specific method must be completed (e.g., PASSWORD).
 * CHOICE: User selects from multiple enrolled methods (e.g., TOTP or EMAIL_OTP or FACE).
 */
public enum StepType {
    SEQUENTIAL,
    CHOICE
}
