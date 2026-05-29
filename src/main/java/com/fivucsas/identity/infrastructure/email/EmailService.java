package com.fivucsas.identity.infrastructure.email;

import java.time.Instant;

public interface EmailService {
    void sendOtp(String to, String code);

    /**
     * Sends a guest invitation email containing a prominent accept link.
     *
     * @param to          recipient email address
     * @param token       the invitation token (used to build the accept link)
     * @param accessStart start of the guest's access window
     * @param accessEnd   end of the guest's access window
     * @param message     optional custom message from the inviter (may be null/blank)
     * @param inviterName display name of the inviting admin (may be null/blank)
     */
    void sendGuestInvitation(String to, String token, Instant accessStart, Instant accessEnd,
                             String message, String inviterName);

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
