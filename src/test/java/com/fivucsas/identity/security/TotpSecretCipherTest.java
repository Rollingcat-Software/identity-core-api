package com.fivucsas.identity.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * BE-H3 (AUDIT_2026-04-19) — TotpSecretCipher unit tests.
 *
 * <p>Covers:
 * <ul>
 *   <li>Round-trip encrypt/decrypt preserves plaintext.</li>
 *   <li>Output carries the {@code enc:v1:} prefix.</li>
 *   <li>Dual-read returns legacy plaintext unchanged.</li>
 *   <li>Tamper detection (AEAD auth-tag mismatch) throws.</li>
 *   <li>Format guard on malformed ciphertext throws.</li>
 *   <li>Fail-fast when the KEK is missing or malformed.</li>
 * </ul>
 */
class TotpSecretCipherTest {

    // Fixed 32-byte key (base64) — tests only, never used in prod.
    private static final String TEST_KEK_B64 = Base64.getEncoder().encodeToString(new byte[]{
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    });

    private TotpSecretCipher cipher;

    @BeforeEach
    void setUp() {
        cipher = new TotpSecretCipher(TEST_KEK_B64, false);
        ReflectionTestUtils.invokeMethod(cipher, "init");
    }

    @Test
    void encrypt_then_decrypt_ShouldRoundTrip() {
        String plaintext = "JBSWY3DPEHPK3PXPABCDEFGHIJKLMNOP";

        String ciphertext = cipher.encrypt(plaintext);

        assertThat(ciphertext).startsWith("enc:v1:");
        assertThat(ciphertext).isNotEqualTo(plaintext);
        assertThat(cipher.decryptIfNeeded(ciphertext)).isEqualTo(plaintext);
    }

    @Test
    void encrypt_TwoCalls_ShouldProduceDifferentCiphertexts_DueToRandomIV() {
        String plaintext = "SAMESECRET";

        String c1 = cipher.encrypt(plaintext);
        String c2 = cipher.encrypt(plaintext);

        assertThat(c1).isNotEqualTo(c2);
        assertThat(cipher.decryptIfNeeded(c1)).isEqualTo(plaintext);
        assertThat(cipher.decryptIfNeeded(c2)).isEqualTo(plaintext);
    }

    @Test
    void decryptIfNeeded_OnLegacyPlaintext_ShouldReturnUnchanged() {
        String legacy = "JBSWY3DPEHPK3PXP";

        assertThat(cipher.decryptIfNeeded(legacy)).isEqualTo(legacy);
        assertThat(cipher.isEncrypted(legacy)).isFalse();
    }

    @Test
    void decryptIfNeeded_OnNull_ShouldReturnNull() {
        assertThat(cipher.decryptIfNeeded(null)).isNull();
        assertThat(cipher.encrypt(null)).isNull();
    }

    @Test
    void encryptIfNeeded_ShouldBeIdempotentForCiphertext() {
        String ciphertext = cipher.encrypt("secret");

        String again = cipher.encryptIfNeeded(ciphertext);

        assertThat(again).isEqualTo(ciphertext); // not double-encrypted
    }

    @Test
    void decryptIfNeeded_TamperedCiphertext_ShouldFail() {
        String ciphertext = cipher.encrypt("secret");
        // Flip one byte inside the base64 payload — AEAD must reject.
        char[] chars = ciphertext.toCharArray();
        int idx = ciphertext.length() - 5;
        chars[idx] = chars[idx] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);

        assertThatThrownBy(() -> cipher.decryptIfNeeded(tampered))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("decryption failed");
    }

    @Test
    void decryptIfNeeded_MalformedBase64_ShouldFail() {
        String malformed = "enc:v1:!!!not-base64!!!";

        assertThatThrownBy(() -> cipher.decryptIfNeeded(malformed))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not base64");
    }

    @Test
    void decryptIfNeeded_TruncatedCiphertext_ShouldFail() {
        // 6 bytes of base64 — shorter than IV + tag (28 bytes).
        String short_ = "enc:v1:" + Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5, 6});

        assertThatThrownBy(() -> cipher.decryptIfNeeded(short_))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("shorter than iv+tag");
    }

    @Test
    void init_WithMissingKey_ShouldFailFast() {
        TotpSecretCipher noKey = new TotpSecretCipher("", false);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(noKey, "init"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("FIVUCSAS_TOTP_ENC_KEY");
    }

    @Test
    void init_WithNullKey_ShouldFailFast() {
        TotpSecretCipher noKey = new TotpSecretCipher(null, false);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(noKey, "init"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("FIVUCSAS_TOTP_ENC_KEY");
    }

    @Test
    void init_WithInvalidBase64_ShouldFailFast() {
        TotpSecretCipher bad = new TotpSecretCipher("!!!not-base64!!!", false);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(bad, "init"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not valid base64");
    }

    @Test
    void init_WithWrongKeyLength_ShouldFailFast() {
        // 16 bytes → 128 bits; we require 256.
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
        TotpSecretCipher bad = new TotpSecretCipher(shortKey, false);

        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(bad, "init"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void strictMode_PlaintextRead_ShouldThrow() {
        TotpSecretCipher strict = new TotpSecretCipher(TEST_KEK_B64, true);
        ReflectionTestUtils.invokeMethod(strict, "init");

        assertThatThrownBy(() -> strict.decryptIfNeeded("JBSWY3DPEHPK3PXP"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Refusing to read plaintext TOTP");
    }

    @Test
    void strictMode_CiphertextRead_ShouldStillWork() {
        TotpSecretCipher strict = new TotpSecretCipher(TEST_KEK_B64, true);
        ReflectionTestUtils.invokeMethod(strict, "init");
        String ciphertext = cipher.encrypt("JBSWY3DPEHPK3PXP"); // produced via lenient cipher, same KEK

        // Strict mode MUST still read valid ciphertext — it only rejects plaintext.
        assertThat(strict.decryptIfNeeded(ciphertext)).isEqualTo("JBSWY3DPEHPK3PXP");
    }

    @Test
    void strictMode_Null_ShouldStillReturnNull() {
        TotpSecretCipher strict = new TotpSecretCipher(TEST_KEK_B64, true);
        ReflectionTestUtils.invokeMethod(strict, "init");

        assertThat(strict.decryptIfNeeded(null)).isNull();
    }

    @Test
    void isEncrypted_FormatGuard() {
        assertThat(cipher.isEncrypted(null)).isFalse();
        assertThat(cipher.isEncrypted("")).isFalse();
        assertThat(cipher.isEncrypted("plaintext")).isFalse();
        assertThat(cipher.isEncrypted("enc:v1:something")).isTrue();
    }
}
