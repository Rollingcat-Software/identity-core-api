package com.fivucsas.identity.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-256 hasher for refresh-token secrets at rest (P1-1, see
 * {@code SECURITY_REVIEW_2026-05-01.md} §P1-1).
 *
 * <p>Refresh tokens are minted with wire format {@code <id>.<secret>} where
 * {@code <secret>} is a high-entropy random string. Only {@code sha256(secret)}
 * is stored. SHA-256 (rather than bcrypt/argon2) is appropriate here because
 * the secret is itself >= 256 bits of entropy — no offline brute-force gain.
 *
 * <p>Comparison must use {@link MessageDigest#isEqual(byte[], byte[])} for
 * constant-time semantics.
 */
public final class RefreshTokenHasher {

    private RefreshTokenHasher() {
        // utility class
    }

    /**
     * Computes SHA-256 of the given secret string.
     *
     * @param secret the refresh-token secret-half (never the full wire token)
     * @return 32-byte digest
     */
    public static byte[] sha256(String secret) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(secret.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every JRE — this would be a JVM bug.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
