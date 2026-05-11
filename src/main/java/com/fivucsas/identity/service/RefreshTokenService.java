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

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService implements com.fivucsas.identity.application.port.output.RefreshTokenPort {

    /**
     * Length (bytes) of the random secret-half. 32 bytes = 256 bits, which is
     * larger than SHA-256's collision-resistance bound — so storing only the
     * digest gives no offline brute-force advantage versus storing the secret
     * directly. SECURITY_REVIEW_2026-05-01.md §P1-1.
     */
    private static final int SECRET_BYTES = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

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

        // P1-1 (2026-05-02): wire format is `<id>.<secret>` where `<secret>` is
        // a 32-byte URL-safe random. Only sha256(secret) is persisted in
        // token_secret_hash.
        //
        // T4-D (2026-05-11, V60): the dual-written plaintext `token` column was
        // dropped after the 7-day soak window closed. The wire token is now
        // carried back to the caller via the {@code @Transient} {@code token}
        // field on the entity — set BEFORE save so the response body can read
        // it via {@code refreshToken.getToken()}, never persisted, never
        // re-hydrated. After this method returns the secret is unrecoverable
        // outside of what the calling controller wrote into the HTTP response.
        UUID tokenId = UUID.randomUUID();
        String secret = generateSecret();
        String wireToken = tokenId + "." + secret;
        byte[] secretHash = RefreshTokenHasher.sha256(secret);

        RefreshToken refreshToken = RefreshToken.builder()
                .id(tokenId)
                .user(user)
                .tokenSecretHash(secretHash)
                .familyId(familyId)
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        // Transient one-shot exposure of the wire token. JPA does not persist
        // this field (it is annotated @Transient); a subsequent findById()
        // returns a row with token == null. The wire token lives only on this
        // in-memory reference until the caller finishes building the response.
        saved.setToken(wireToken);
        return saved;
    }

    private static String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
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

    /**
     * Locate a refresh token by the raw value the client presented.
     *
     * <p>P1-1 (2026-05-02) wire format: {@code <id>.<secret>}. Lookup goes by
     * id and constant-time-compares {@code sha256(secret)} against
     * {@code token_secret_hash}.</p>
     *
     * <p>T4-D (2026-05-11, V60): the legacy plaintext-column dual-read
     * fallback was removed after the 7-day soak. Any token presented in a
     * pre-V55 shape (no {@code .} separator, no id prefix) now resolves to
     * {@link TokenRevokedException} — by 2026-05-11 every such token has
     * either rolled off via the 7-day TTL or been rotated.</p>
     *
     * <p>A hash mismatch on a known id is treated as "wrong token" (404-shaped),
     * not "reused token" — only an explicit revoked-and-presented token triggers
     * family revocation in {@link #verifyExpiration(RefreshToken)}.
     */
    @Transactional(readOnly = true)
    public RefreshToken findByToken(String token) {
        return findByHashedWireToken(token)
                .orElseThrow(() -> new TokenRevokedException("Refresh token not found or has been revoked"));
    }

    /**
     * Returns a present {@code Optional} only when {@code raw} is a well-formed
     * {@code <id>.<secret>} pair AND the row's {@code token_secret_hash} matches
     * {@code sha256(secret)} in constant time.
     */
    private Optional<RefreshToken> findByHashedWireToken(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        int dot = raw.indexOf('.');
        if (dot <= 0 || dot == raw.length() - 1) {
            return Optional.empty();
        }
        String idPart = raw.substring(0, dot);
        String secret = raw.substring(dot + 1);
        UUID tokenId;
        try {
            tokenId = UUID.fromString(idPart);
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
        Optional<RefreshToken> row = refreshTokenRepository.findById(tokenId);
        if (row.isEmpty()) {
            return Optional.empty();
        }
        byte[] storedHash = row.get().getTokenSecretHash();
        if (storedHash == null) {
            // Row was minted before this PR — fall through to plaintext path.
            return Optional.empty();
        }
        byte[] presentedHash = RefreshTokenHasher.sha256(secret);
        if (!MessageDigest.isEqual(storedHash, presentedHash)) {
            // Wrong secret for a real id. Treat as "not found" — caller throws
            // TokenRevokedException("not found"). Do NOT trigger family revoke
            // here: only verifyExpiration's revoked-token path qualifies as
            // "reuse-detected" per RFC 6749 §10.4.
            return Optional.empty();
        }
        return row;
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
