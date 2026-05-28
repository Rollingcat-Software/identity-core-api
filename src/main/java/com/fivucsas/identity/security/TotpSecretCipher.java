package com.fivucsas.identity.security;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-GCM 256 cipher for TOTP shared secrets (BE-H3, AUDIT_2026-04-19).
 *
 * <p>Storage format (ciphertext column): {@code enc:v1:<base64(iv||ciphertext||tag)>}.
 * <ul>
 *   <li>12-byte random IV per encryption (never reused).</li>
 *   <li>AES/GCM/NoPadding, 128-bit auth tag.</li>
 *   <li>KEK loaded from environment variable {@code FIVUCSAS_TOTP_ENC_KEY} as a
 *       base64-encoded 32-byte value. Property key: {@code fivucsas.totp.enc-key}.</li>
 * </ul>
 *
 * <p><b>Fail-fast</b>: if the key is missing, malformed, or not 32 bytes the
 * bean refuses to initialize, preventing silent plaintext fallback.
 *
 * <p>Dual-read helper {@link #decryptIfNeeded(String)} returns legacy plaintext
 * values unchanged so the migration window does not break existing users.
 * Writes go through {@link #encrypt(String)} so every new/updated row is
 * encrypted.
 */
@Component
@Slf4j
public class TotpSecretCipher {

    public static final String CIPHERTEXT_PREFIX = "enc:v1:";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int KEY_LENGTH_BYTES = 32;

    private final String rawKey;
    private final boolean rejectPlaintext;
    private final SecureRandom rng = new SecureRandom();
    private SecretKey secretKey;

    public TotpSecretCipher(
            @Value("${fivucsas.totp.enc-key:}") String rawKey,
            @Value("${fivucsas.totp.reject-plaintext:false}") boolean rejectPlaintext) {
        this.rawKey = rawKey;
        this.rejectPlaintext = rejectPlaintext;
    }

    @PostConstruct
    void init() {
        if (rawKey == null || rawKey.isBlank()) {
            throw new IllegalStateException(
                    "FIVUCSAS_TOTP_ENC_KEY is not configured. "
                            + "TOTP secret cipher cannot boot without a KEK. "
                            + "Generate one with: openssl rand -base64 32 "
                            + "and set FIVUCSAS_TOTP_ENC_KEY in the environment.");
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(rawKey.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "FIVUCSAS_TOTP_ENC_KEY is not valid base64. "
                            + "Expected base64-encoded 32 bytes (openssl rand -base64 32).",
                    e);
        }
        if (keyBytes.length != KEY_LENGTH_BYTES) {
            throw new IllegalStateException(
                    "FIVUCSAS_TOTP_ENC_KEY must decode to exactly "
                            + KEY_LENGTH_BYTES + " bytes (got "
                            + keyBytes.length + "). "
                            + "Regenerate with: openssl rand -base64 32");
        }
        this.secretKey = new SecretKeySpec(keyBytes, "AES");
        log.info("TotpSecretCipher initialized (AES-GCM-256, KEK fingerprint sha256[0..8]={})",
                keyFingerprint(keyBytes));
    }

    /**
     * Encrypt a plaintext TOTP secret. Always returns a value prefixed with
     * {@link #CIPHERTEXT_PREFIX}. Calling this on a value that is already
     * encrypted will double-encrypt — callers should use
     * {@link #encryptIfNeeded(String)} when unsure.
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            rng.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            ByteBuffer buf = ByteBuffer.allocate(iv.length + ct.length);
            buf.put(iv).put(ct);
            return CIPHERTEXT_PREFIX + Base64.getEncoder().encodeToString(buf.array());
        } catch (GeneralSecurityExceptionWrapper e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("TOTP secret encryption failed", e);
        }
    }

    /**
     * Dual-read. If {@code stored} starts with {@link #CIPHERTEXT_PREFIX},
     * decrypt and return plaintext. Otherwise treat as legacy plaintext and
     * return unchanged. Null in → null out.
     *
     * <p>S14 (security review): when {@code fivucsas.totp.reject-plaintext} is
     * {@code true}, a legacy (un-encrypted) value is treated as a fatal data
     * integrity error and this method throws {@link IllegalStateException}
     * instead of silently returning the plaintext. Enable only after every
     * legacy row has been migrated to {@code enc:v1:...}.</p>
     */
    public String decryptIfNeeded(String stored) {
        if (stored == null) {
            return null;
        }
        if (!isEncrypted(stored)) {
            if (rejectPlaintext) {
                throw new IllegalStateException(
                        "Plaintext TOTP secret rejected: "
                                + "fivucsas.totp.reject-plaintext is enabled but a "
                                + "non-encrypted secret was encountered. Migrate legacy "
                                + "rows (fivucsas.totp.migrate-on-boot) before enabling "
                                + "reject-plaintext.");
            }
            return stored; // legacy plaintext row — re-encrypted on next write
        }
        String payload = stored.substring(CIPHERTEXT_PREFIX.length());
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(payload);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Malformed TOTP ciphertext: not base64", e);
        }
        if (raw.length <= IV_LENGTH_BYTES + (TAG_LENGTH_BITS / 8)) {
            throw new IllegalStateException(
                    "Malformed TOTP ciphertext: payload shorter than iv+tag");
        }
        byte[] iv = new byte[IV_LENGTH_BYTES];
        byte[] ct = new byte[raw.length - IV_LENGTH_BYTES];
        System.arraycopy(raw, 0, iv, 0, IV_LENGTH_BYTES);
        System.arraycopy(raw, IV_LENGTH_BYTES, ct, 0, ct.length);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            // AEAD auth failure → tampering, wrong key, or corruption.
            throw new IllegalStateException(
                    "TOTP secret decryption failed (auth tag mismatch or wrong key)", e);
        }
    }

    /** Encrypt unless already encrypted. Idempotent for ciphertext inputs. */
    public String encryptIfNeeded(String value) {
        if (value == null) {
            return null;
        }
        return isEncrypted(value) ? value : encrypt(value);
    }

    public boolean isEncrypted(String value) {
        return value != null && value.startsWith(CIPHERTEXT_PREFIX);
    }

    private static String keyFingerprint(byte[] keyBytes) {
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(keyBytes);
            StringBuilder sb = new StringBuilder(16);
            for (int i = 0; i < 4; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }

    /** Marker to allow rethrow without wrapping; currently unused but kept for clarity. */
    private static final class GeneralSecurityExceptionWrapper extends RuntimeException {
    }
}
