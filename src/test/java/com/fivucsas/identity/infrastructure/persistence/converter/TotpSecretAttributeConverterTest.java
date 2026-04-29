package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.security.TotpSecretCipher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * EDGE-P1 #7 (AUDIT_2026-04-28) — TotpSecretAttributeConverter unit tests.
 *
 * <p>Covers:
 * <ul>
 *   <li>Plaintext → DB column → {@code enc:v1:} ciphertext.</li>
 *   <li>DB ciphertext → entity attribute → plaintext (round-trip).</li>
 *   <li>Already-encrypted plaintext is NOT double-encrypted (idempotency).</li>
 *   <li>Legacy plaintext on read passes through unchanged (dual-read).</li>
 *   <li>{@code null} in → {@code null} out on both directions.</li>
 *   <li>Fails loud when the cipher static holder has not been wired
 *       (catches "Spring not booted" misconfiguration in production).</li>
 * </ul>
 */
class TotpSecretAttributeConverterTest {

    private static final String TEST_KEK_B64 = Base64.getEncoder().encodeToString(new byte[]{
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
            16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1
    });

    private TotpSecretCipher cipher;
    private TotpSecretAttributeConverter converter;

    @BeforeEach
    void setUp() {
        cipher = new TotpSecretCipher(TEST_KEK_B64);
        ReflectionTestUtils.invokeMethod(cipher, "init");
        TotpSecretAttributeConverter.setCipherForTesting(cipher);
        converter = new TotpSecretAttributeConverter();
    }

    @AfterEach
    void tearDown() {
        TotpSecretAttributeConverter.setCipherForTesting(null);
    }

    @Test
    void plaintextPlugged_intoDbColumn_isEncryptedWithV1Prefix() {
        String plaintext = "JBSWY3DPEHPK3PXP";

        String stored = converter.convertToDatabaseColumn(plaintext);

        assertThat(stored).isNotNull();
        assertThat(stored).startsWith(TotpSecretCipher.CIPHERTEXT_PREFIX);
        assertThat(stored).isNotEqualTo(plaintext);
    }

    @Test
    void roundTrip_writeThenRead_returnsOriginalPlaintext() {
        String plaintext = "JBSWY3DPEHPK3PXP";

        String stored = converter.convertToDatabaseColumn(plaintext);
        String read = converter.convertToEntityAttribute(stored);

        assertThat(read).isEqualTo(plaintext);
    }

    @Test
    void writingAlreadyEncryptedValue_isIdempotent_noDoubleEncrypt() {
        // Simulates the manual call-site:
        //   user.enable2FA(totpSecretCipher.encrypt(secret), null)
        // The setter receives ciphertext; the converter must NOT wrap it again.
        String plaintext = "JBSWY3DPEHPK3PXP";
        String alreadyEncrypted = cipher.encrypt(plaintext);

        String stored = converter.convertToDatabaseColumn(alreadyEncrypted);

        // Should match the input exactly — no second encryption envelope.
        assertThat(stored).isEqualTo(alreadyEncrypted);
        // And reading it back still yields the original plaintext (single decrypt).
        assertThat(converter.convertToEntityAttribute(stored)).isEqualTo(plaintext);
    }

    @Test
    void legacyPlaintextRow_onRead_passesThroughUnchanged() {
        // Pre-V42 backfill data: plaintext sitting in the column with no prefix.
        String legacyPlaintext = "JBSWY3DPEHPK3PXP";

        String read = converter.convertToEntityAttribute(legacyPlaintext);

        assertThat(read).isEqualTo(legacyPlaintext);
    }

    @Test
    void nullInput_yieldsNullOutput_onBothDirections() {
        assertThat(converter.convertToDatabaseColumn(null)).isNull();
        assertThat(converter.convertToEntityAttribute(null)).isNull();
    }

    @Test
    void cipherNotWired_throwsLoudErrorOnRead() {
        TotpSecretAttributeConverter.setCipherForTesting(null);

        assertThatThrownBy(() -> converter.convertToDatabaseColumn("anything"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("TotpSecretCipher");
    }
}
