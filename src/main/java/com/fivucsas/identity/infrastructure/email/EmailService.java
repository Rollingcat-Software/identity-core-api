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
}
