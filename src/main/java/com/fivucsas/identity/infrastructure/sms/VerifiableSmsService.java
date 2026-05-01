package com.fivucsas.identity.infrastructure.sms;

/**
 * Extended SMS service that supports native code verification
 * (e.g. Twilio Verify), bypassing the local OTP Redis store.
 */
public interface VerifiableSmsService {

    /**
     * Distinguishable outcomes from a provider-side verify call. Lets callers
     * audit-log a precise reason instead of collapsing both invalid codes
     * AND provider/network errors into a single {@code false}.
     */
    enum VerifyResult {
        /** Provider approved the code. */
        APPROVED,
        /** Provider explicitly rejected the code (wrong digits, expired, etc.). */
        INVALID_CODE,
        /** Provider call failed (network error, 5xx, SDK exception). */
        PROVIDER_ERROR;

        public boolean isApproved() {
            return this == APPROVED;
        }
    }

    /**
     * Verifies the OTP code entered by the user directly with the provider.
     *
     * <p>Returns a typed result so callers can distinguish "user typed wrong
     * code" from "provider unreachable" — useful for audit logs and for
     * deciding whether to surface a transient-error message vs a hard reject.</p>
     *
     * @param phoneNumber E.164 format phone number
     * @param code        Code entered by the user
     * @return outcome of the verification call (never null)
     */
    VerifyResult verifyCodeDetailed(String phoneNumber, String code);

    /**
     * Convenience wrapper retained for legacy call sites that only need a
     * boolean answer. New code should prefer {@link #verifyCodeDetailed}.
     */
    default boolean verifyCode(String phoneNumber, String code) {
        return verifyCodeDetailed(phoneNumber, code).isApproved();
    }
}
