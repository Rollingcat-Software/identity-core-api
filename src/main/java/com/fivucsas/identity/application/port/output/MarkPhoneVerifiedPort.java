package com.fivucsas.identity.application.port.output;

import java.util.UUID;

/**
 * Output port: mark a user's phone number as verified (F2, 2026-06-06).
 *
 * <p>A successful SMS_OTP <em>login</em> proves the user controls the phone on
 * file, exactly like {@code POST /auth/verify-phone} does — but the login
 * handlers historically never set the flag, so a user who only ever authenticates
 * by SMS_OTP still shipped {@code phone_number_verified:false} in the OIDC claim
 * (emitted at {@code OAuth2Service} when the {@code phone} scope is granted).
 *
 * <p>The login MFA handlers ({@code SmsOtpVerifyMfaStepHandler},
 * {@code SmsOtpAuthHandler}) call this on a verified SMS_OTP step. It is keyed by
 * {@code userId} (not the {@code entity.User} aggregate) so the application layer
 * stays clear of the {@code entity.User} hexagonal boundary — the
 * {@code entity.User} mutation + persist lives entirely in the infrastructure
 * adapter ({@code MarkPhoneVerifiedAdapter}).
 *
 * <p>Idempotent: a no-op when the user is already phone-verified or the id does
 * not resolve. This does NOT make phone mandatory anywhere — it only corrects the
 * claim WHEN a user authenticates by SMS_OTP.
 */
public interface MarkPhoneVerifiedPort {

    /**
     * Mark the given user's phone number as verified, if not already.
     *
     * @param userId the id of the user who just passed an SMS_OTP step
     */
    void markPhoneVerified(UUID userId);
}
