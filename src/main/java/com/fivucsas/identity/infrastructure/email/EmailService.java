package com.fivucsas.identity.infrastructure.email;

import java.time.Instant;

public interface EmailService {

    /**
     * Sends a branded, bilingual (EN/TR) one-time-code email.
     *
     * <p>Prefer the {@code purpose}-aware overload below — it labels the code
     * correctly (login verification vs. registration vs. account-link vs.
     * password reset) and is what new call-sites should use. This
     * zero-extra-argument form is kept for backwards compatibility and is
     * equivalent to {@code sendOtp(to, code, OtpPurpose.LOGIN_VERIFICATION,
     * null)} (English login-verification copy).</p>
     *
     * @param to   recipient email address
     * @param code the one-time code
     */
    void sendOtp(String to, String code);

    /**
     * Sends a branded, bilingual (EN/TR) one-time-code email whose subject and
     * copy are tailored to the {@code purpose} of the code.
     *
     * <p>The body is an inline-styled HTML message (FIVUCSAS wordmark header,
     * the code shown prominently, an expiry note, a plain footer) with a
     * plain-text fallback for clients that cannot render HTML. The recipient's
     * locale selects EN or TR copy; any unsupported/blank locale falls back to
     * English (mirrors {@link #sendGuestInvitation}).</p>
     *
     * @param to      recipient email address
     * @param code    the one-time code
     * @param purpose what the code is for — drives the subject + body wording
     *                (null is treated as {@link OtpPurpose#LOGIN_VERIFICATION})
     * @param locale  BCP-47 language tag of the recipient ("tr"/"en"; null/blank → EN)
     */
    void sendOtp(String to, String code, OtpPurpose purpose, String locale);

    /**
     * Sends a guest invitation email containing a prominent accept link.
     *
     * <p>The body is rendered in the recipient's locale (EN or TR). Any
     * unsupported/blank locale falls back to English.</p>
     *
     * @param to          recipient email address
     * @param token       the invitation token (used to build the accept link)
     * @param accessStart start of the guest's access window
     * @param accessEnd   end of the guest's access window
     * @param message     optional custom message from the inviter (may be null/blank)
     * @param inviterName display name of the inviting admin (may be null/blank)
     * @param tenantName  the inviting organisation's name (may be null/blank)
     * @param locale      BCP-47 language tag of the recipient ("tr"/"en"; null/blank → EN)
     */
    void sendGuestInvitation(String to, String token, Instant accessStart, Instant accessEnd,
                             String message, String inviterName, String tenantName, String locale);

    /**
     * Sends the email-verification mail for a self-service tenant onboarding.
     *
     * <p>The link points at the frontend's verify-email page; following it
     * verifies the admin's email and activates the new tenant (unless admin
     * approval is required).</p>
     *
     * @param to          admin email address
     * @param adminName   admin first name (for the greeting; may be null/blank)
     * @param orgName     the organisation that was just registered
     * @param token       the email-verification token (used to build the link)
     */
    void sendTenantOnboardingVerification(String to, String adminName, String orgName, String token);
}
