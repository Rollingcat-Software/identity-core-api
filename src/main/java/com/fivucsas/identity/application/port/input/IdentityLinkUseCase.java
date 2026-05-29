package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.response.IdentityMeResponse;

import java.util.UUID;

/**
 * Input port for Phase-2 account linking (see
 * {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md} § "Phase 2").
 *
 * <p>Lets a person fold another tenant account (a different email) into their
 * platform-level identity after proving control of the other email (OTP) AND
 * stepping up on the caller (fresh password re-entry). All operations are
 * derived from the AUTHENTICATED caller's identity — a caller can only ever
 * operate on their own identity.</p>
 */
public interface IdentityLinkUseCase {

    /**
     * Begins a link: validates the target email is a linkable membership and
     * sends a one-time code to it (proof of email control). Idempotent-friendly
     * and rate-limited.
     *
     * @param callerUserId the authenticated caller's user id
     * @param targetEmail  the email of the account to link
     */
    void initiateLink(UUID callerUserId, String targetEmail);

    /**
     * Completes a link: verifies the OTP sent to {@code targetEmail} AND the
     * caller's step-up password, then re-points the target membership's
     * {@code identity_id} to the caller's identity, moves the email into the
     * caller's identity (verified), and deletes the target's now-orphaned
     * identity. Idempotent if the membership already belongs to the caller's
     * identity.
     *
     * @param callerUserId   the authenticated caller's user id
     * @param targetEmail    the email being linked
     * @param otp            the one-time code sent to {@code targetEmail}
     * @param stepUpPassword the caller's current password (step-up re-auth)
     */
    void confirmLink(UUID callerUserId, String targetEmail, String otp, String stepUpPassword);

    /**
     * Reverses a link: gives the named membership a fresh identity (plus an
     * email row) and re-points it. The caller may only unlink memberships within
     * their OWN identity; a membership is never left with a NULL identity.
     *
     * @param callerUserId     the authenticated caller's user id
     * @param membershipUserId the membership (users row) to split off
     */
    void unlink(UUID callerUserId, UUID membershipUserId);

    /**
     * The person view for the caller's identity: emails + memberships across all
     * tenants.
     *
     * @param callerUserId the authenticated caller's user id
     * @return the caller's identity, emails and memberships
     */
    IdentityMeResponse getMyIdentity(UUID callerUserId);
}
