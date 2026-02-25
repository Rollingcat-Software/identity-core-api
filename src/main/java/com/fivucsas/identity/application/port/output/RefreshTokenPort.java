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

    RefreshToken findByToken(String token);

    RefreshToken verifyExpiration(RefreshToken token);

    void revokeToken(String token);

    void revokeAllUserTokens(User user);

    RefreshToken rotateRefreshToken(RefreshToken oldToken, String ipAddress, String userAgent);

    int deleteExpiredTokens();
}
