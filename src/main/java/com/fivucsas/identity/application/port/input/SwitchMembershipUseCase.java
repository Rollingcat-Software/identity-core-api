package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.dto.AuthResponse;

import java.util.List;
import java.util.UUID;

/**
 * Input port (use case) for Phase-5 in-session membership switching — an
 * authenticated person assumes another of THEIR OWN linked memberships without
 * re-login (a token exchange / account switch, NOT a privilege grant).
 *
 * <p>See {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md} § "Phase 5".</p>
 */
public interface SwitchMembershipUseCase {

    /**
     * Switch the caller's session to the target membership.
     *
     * @param callerUserId  the authenticated caller's user id
     * @param targetUserId  the membership the caller wants to assume
     * @param stepUpPassword the caller's current password — REQUIRED only when
     *                       {@code app.identity.require-stepup-on-switch=true},
     *                       otherwise ignored
     * @param amr           the caller's current {@code amr} claim to carry over
     * @param authTime      the caller's current {@code auth_time} (epoch seconds)
     *                      to carry over, or {@code null}
     * @param ipAddress     request IP (for the new refresh-token row)
     * @param userAgent     request User-Agent (for the new refresh-token row)
     * @return a {@code /auth/login}-shaped {@link AuthResponse} carrying the new
     *         access+refresh token pair minted AS the target membership
     */
    AuthResponse switchMembership(UUID callerUserId,
                                  UUID targetUserId,
                                  String stepUpPassword,
                                  List<String> amr,
                                  Long authTime,
                                  String ipAddress,
                                  String userAgent);
}
