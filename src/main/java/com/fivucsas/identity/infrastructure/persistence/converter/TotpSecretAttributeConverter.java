package com.fivucsas.identity.infrastructure.persistence.converter;

import com.fivucsas.identity.security.TotpSecretCipher;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * JPA AttributeConverter that transparently encrypts/decrypts the
 * {@code two_factor_secret} column on the {@code users} table.
 *
 * <p><b>Why this exists (EDGE-P1 #7, AUDIT_2026-04-28):</b>
 * Before this converter, every callsite that wrote {@code User.twoFactorSecret}
 * had to remember to call {@link TotpSecretCipher#encrypt(String)} manually.
 * Any future code path that bypassed the cipher and wrote raw plaintext would
 * fail the V42 {@code two_factor_secret_encrypted} CHECK constraint at flush
 * time as a confusing 500 — instead of being prevented at the entity layer.
 *
 * <p>By annotating the field with
 * {@code @Convert(converter = TotpSecretAttributeConverter.class)}, the cipher
 * is invoked at the persistence boundary. Callers can write plaintext to the
 * setter and reads return plaintext. Wire-format on disk is always
 * {@code enc:v1:<base64>}.
 *
 * <p><b>Idempotency:</b> The underlying {@code TotpSecretCipher} is dual-read
 * tolerant — {@link TotpSecretCipher#encryptIfNeeded(String)} no-ops on
 * already-encrypted values, and {@link TotpSecretCipher#decryptIfNeeded(String)}
 * passes legacy plaintext through. Existing manual callsites
 * (OtpController, TotpAuthHandler) therefore remain correct after this
 * converter is introduced — the converter sees the already-encrypted value
 * and leaves it alone (no double-encrypt).
 *
 * <p><b>DI of cipher:</b> JPA AttributeConverters are instantiated by the
 * persistence provider, not by Spring. To still inject the
 * {@link TotpSecretCipher} singleton we use a static holder populated from a
 * Spring-managed initializer bean. This pattern is well-trodden (Hibernate's
 * own docs use it) and avoids requiring callers to register a
 * {@code SpringBeanContainer} manually.
 */
@Converter
public class TotpSecretAttributeConverter implements AttributeConverter<String, String> {

    private static volatile TotpSecretCipher cipher;

    /**
     * Spring-managed initializer: copies the {@link TotpSecretCipher}
     * singleton into the static holder so non-Spring-instantiated converters
     * can reach it. Marked {@code @Component} so Spring wires it on boot.
     */
    @Component
    @RequiredArgsConstructor
    static class CipherHolderInitializer {

        private final TotpSecretCipher injectedCipher;

        @PostConstruct
        void init() {
            TotpSecretAttributeConverter.cipher = injectedCipher;
        }
    }

    /**
     * Plaintext (entity) → ciphertext (DB). Idempotent: if the value is
     * already in {@code enc:v1:} form (e.g. callers that still encrypt
     * manually for backward compatibility), it is returned unchanged.
     */
    @Override
    public String convertToDatabaseColumn(String plaintextOrCiphertext) {
        if (plaintextOrCiphertext == null) {
            return null;
        }
        TotpSecretCipher c = requireCipher();
        return c.encryptIfNeeded(plaintextOrCiphertext);
    }

    /**
     * Ciphertext (DB) → plaintext (entity). Dual-read tolerant: legacy
     * plaintext rows (pre-V42 backfill) pass through unchanged.
     */
    @Override
    public String convertToEntityAttribute(String stored) {
        if (stored == null) {
            return null;
        }
        TotpSecretCipher c = requireCipher();
        return c.decryptIfNeeded(stored);
    }

    private static TotpSecretCipher requireCipher() {
        TotpSecretCipher c = cipher;
        if (c == null) {
            // Spring context not yet wired (would only happen during very
            // early boot or in a non-Spring test). Fail loud rather than
            // silently leaking plaintext to the DB.
            throw new IllegalStateException(
                "TotpSecretAttributeConverter accessed before Spring "
                    + "initialized TotpSecretCipher. This is a wiring bug.");
        }
        return c;
    }

    /**
     * Test hook. Allows unit tests to inject a cipher without standing up a
     * full Spring context. Production code MUST NOT call this.
     */
    static void setCipherForTesting(TotpSecretCipher c) {
        cipher = c;
    }
}
