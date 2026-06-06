package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;

/**
 * Output port for refresh token management.
 *
 * Abstracts refresh token persistence and lifecycle operations
 * behind a port interface for hexagonal architecture compliance.
 */
public interface RefreshTokenPort {

    RefreshToken createRefreshToken(User user, String ipAddress, String userAgent);

    /**
     * Mint a refresh token bound to the issuing OAuth2 {@code clientId} (API-2,
     * V84). Pass {@code null} for non-OAuth / legacy mints (client-unbound). The
     * default delegates to the unbound 3-arg form so existing implementations and
     * test doubles stay source-compatible.
     */
    default RefreshToken createRefreshToken(User user, String ipAddress, String userAgent, String clientId) {
        return createRefreshToken(user, ipAddress, userAgent);
    }

    RefreshToken findByToken(String token);

    RefreshToken verifyExpiration(RefreshToken token);

    void revokeToken(String token);

    void revokeAllUserTokens(User user);

    RefreshToken rotateRefreshToken(RefreshToken oldToken, String ipAddress, String userAgent);

    int deleteExpiredTokens();
}
