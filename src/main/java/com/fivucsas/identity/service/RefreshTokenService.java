package com.fivucsas.identity.service;

import com.fivucsas.identity.domain.exception.TokenExpiredException;
import com.fivucsas.identity.domain.exception.TokenRevokedException;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService implements com.fivucsas.identity.application.port.output.RefreshTokenPort {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration:604800000}") // 7 days in milliseconds
    private long refreshTokenDurationMs;

    @Transactional
    public RefreshToken createRefreshToken(User user, String ipAddress, String userAgent) {
        log.info("Creating refresh token for user: {}", user.getEmail());

        // Revoke existing active tokens for security (optional - can allow multiple devices)
        revokeAllUserTokens(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isExpired()) {
            refreshTokenRepository.delete(token);
            throw new TokenExpiredException("Refresh");
        }

        if (token.isRevoked()) {
            throw new TokenRevokedException();
        }

        return token;
    }

    @Transactional(readOnly = true)
    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenRevokedException("Refresh token not found or has been revoked"));
    }

    @Transactional
    public void revokeToken(String token) {
        RefreshToken refreshToken = findByToken(token);
        refreshToken.revoke();
        refreshTokenRepository.save(refreshToken);
        log.info("Refresh token revoked for user: {}", refreshToken.getUser().getEmail());
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        int revokedCount = refreshTokenRepository.revokeAllUserTokens(user, Instant.now());
        log.info("Revoked {} refresh tokens for user: {}", revokedCount, user.getEmail());
    }

    @Transactional
    public RefreshToken rotateRefreshToken(RefreshToken oldToken, String ipAddress, String userAgent) {
        log.info("Rotating refresh token for user: {}", oldToken.getUser().getEmail());

        // Revoke old token
        oldToken.revoke();
        refreshTokenRepository.save(oldToken);

        // Create new token
        return createRefreshToken(oldToken.getUser(), ipAddress, userAgent);
    }

    @Transactional
    public int deleteExpiredTokens() {
        int deletedCount = refreshTokenRepository.deleteExpiredTokens(Instant.now());
        log.info("Deleted {} expired refresh tokens", deletedCount);
        return deletedCount;
    }
}
