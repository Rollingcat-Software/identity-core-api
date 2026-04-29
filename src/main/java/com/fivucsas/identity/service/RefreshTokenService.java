package com.fivucsas.identity.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
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
    private final AuditLogPort auditLogPort;

    @Value("${jwt.refresh-expiration:604800000}") // 7 days in milliseconds
    private long refreshTokenDurationMs;

    @Transactional
    public RefreshToken createRefreshToken(User user, String ipAddress, String userAgent) {
        // Initial login mints a fresh family — no parent to inherit from.
        return createRefreshTokenInFamily(user, UUID.randomUUID(), ipAddress, userAgent);
    }

    /**
     * Internal helper: mint a refresh token attached to a specific rotation
     * family. Used by both initial login (fresh family) and rotation
     * (parent family inherited).
     */
    private RefreshToken createRefreshTokenInFamily(User user, UUID familyId,
                                                    String ipAddress, String userAgent) {
        log.info("Creating refresh token for user: {} (family={})", user.getEmail(), familyId);

        // BE-M5 (2026-04-19): do NOT revoke all existing tokens here. Previously
        // this path unconditionally called revokeAllUserTokens(user), which broke
        // legitimate multi-device sessions: a user signing in on their phone would
        // silently log themselves out of their laptop.
        //
        // Invariant (new): createRefreshToken mints a new token alongside any
        // existing active tokens. Rotation of a *specific* token (login refresh)
        // happens in rotateRefreshToken() below, which revokes only the one being
        // replaced. Cross-device bulk revocation is a user-initiated operation
        // (see SessionService) and not a side effect of normal login.

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .familyId(familyId)
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
            // Reuse-detection (Sec-P2 #6): a presented-but-revoked token means
            // either the user resubmitted an old proof OR an attacker captured
            // it before rotation. RFC 6749 §10.4 + OAuth 2.0 Security BCP §4.13
            // require revoking every descendant in the rotation family so the
            // attacker's "winning" token is killed even if the legitimate
            // client races ahead.
            int killed = refreshTokenRepository.revokeFamily(token.getFamilyId(), Instant.now());
            log.warn("Refresh-token reuse detected for user={} family={} — revoked {} family member(s)",
                    token.getUser().getEmail(), token.getFamilyId(), killed);
            auditLogPort.logSecurityEvent(
                    token.getUser().getId().toString(),
                    "REFRESH_TOKEN_REUSE_DETECTED",
                    token.getIpAddress(),
                    "family=" + token.getFamilyId() + " revoked=" + killed);
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
        log.info("Rotating refresh token for user: {} (family={})",
                oldToken.getUser().getEmail(), oldToken.getFamilyId());

        // Revoke old token, then mint a successor that inherits the rotation
        // family — every token derived from a single login shares one family
        // so reuse-detection can revoke them all at once (Sec-P2 #6).
        oldToken.revoke();
        refreshTokenRepository.save(oldToken);
        return createRefreshTokenInFamily(oldToken.getUser(), oldToken.getFamilyId(),
                ipAddress, userAgent);
    }

    @Transactional
    public int deleteExpiredTokens() {
        int deletedCount = refreshTokenRepository.deleteExpiredTokens(Instant.now());
        log.info("Deleted {} expired refresh tokens", deletedCount);
        return deletedCount;
    }
}
