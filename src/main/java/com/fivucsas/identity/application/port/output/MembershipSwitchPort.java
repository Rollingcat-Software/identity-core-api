package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.dto.AuthResponse;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for the user/membership-side operations needed by Phase-5
 * in-session membership switching ({@code SwitchMembershipService}).
 *
 * <p><b>Why this port exists (hexagonal boundary).</b> The switch flow must read
 * a {@code users} row (the target MEMBERSHIP), assert it is currently switchable
 * (ACTIVE, not locked/suspended/soft-deleted, tenant ACTIVE) and mint a fresh
 * access+refresh token pair AS that membership — REUSING the existing
 * post-login token-mint path ({@code JwtService} + {@code RefreshTokenService}).
 * The JPA {@code entity.User} type is fenced behind the
 * {@code UserDomainBoundaryTest} ArchUnit ratchet and MUST NOT be imported from
 * {@code application..}; this port exposes only plain DTOs / UUIDs so the
 * application service stays boundary-clean. The implementing adapter lives in
 * {@code infrastructure..} (the official bridge) and is the only place that
 * touches {@code entity.User} / {@code RefreshTokenService}.</p>
 */
public interface MembershipSwitchPort {

    /**
     * A read-only projection of a switch-target membership ({@code users} row)
     * plus the booleans the switch HARD GATE / switchability checks need —
     * resolved against the JPA entity inside the adapter so the application
     * service never inspects {@code entity.User} directly.
     *
     * @param userId        the target membership's user id
     * @param identityId    the target's platform identity id (may be {@code null}
     *                      if not yet backfilled — treated as a hard-gate failure)
     * @param email         the target membership's email (the token subject)
     * @param tenantId      the target's tenant id
     * @param userActive    the target user is ACTIVE (status==ACTIVE), NOT
     *                      currently locked and NOT soft-deleted
     * @param tenantActive  the target's tenant is ACTIVE
     */
    record SwitchTargetView(
            UUID userId,
            UUID identityId,
            String email,
            UUID tenantId,
            boolean userActive,
            boolean tenantActive) {
    }

    /**
     * Resolves the switch target by user id (tenant filter bypassed — the
     * caller's own memberships span tenants by design), if a non-deleted user
     * exists. Empty means the target user id does not resolve to a row.
     */
    Optional<SwitchTargetView> findSwitchTarget(UUID targetUserId);

    /**
     * Verifies that {@code rawPassword} matches the stored password hash of the
     * given user. Used ONLY when {@code app.identity.require-stepup-on-switch} is
     * enabled. Returns false if the user has no password set / does not exist.
     */
    boolean verifyPassword(UUID userId, String rawPassword);

    /**
     * Mints a NEW access+refresh token pair AS the target membership and returns
     * it in the SAME {@link AuthResponse} shape as {@code /auth/login} so the web
     * swaps tokens identically.
     *
     * <p>REUSES the post-login token-mint path:
     * <ul>
     *   <li>access token via {@code JwtService.generateToken(claims, targetEmail)}
     *       — subject = target email, carrying over the caller's {@code amr} +
     *       {@code auth_time} and stamping {@code act} = caller user id;</li>
     *   <li>refresh token via {@code RefreshTokenService.createRefreshToken(
     *       targetUser, ip, userAgent)} — a NORMAL refresh token for the target
     *       user, so subsequent {@code /auth/refresh} works as that membership.</li>
     * </ul>
     *
     * @param targetUserId   the membership being assumed (its email is the subject)
     * @param amr            the caller's carried-over {@code amr} claim (may be empty)
     * @param authTime       the caller's carried-over {@code auth_time} (epoch
     *                       seconds), or {@code null} to omit
     * @param actorUserId    the caller user id, stamped as {@code act} (and
     *                       {@code switched_from}) for traceability
     * @param ipAddress      request IP (for the refresh-token row)
     * @param userAgent      request User-Agent (for the refresh-token row)
     * @return the login-shaped response carrying the new token pair + target user
     */
    AuthResponse mintSwitchedTokens(UUID targetUserId,
                                    List<String> amr,
                                    Long authTime,
                                    UUID actorUserId,
                                    String ipAddress,
                                    String userAgent);
}
