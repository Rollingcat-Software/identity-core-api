package com.fivucsas.identity.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One-shot re-encryption job for legacy-plaintext {@code users.two_factor_secret}
 * values (BE-H3, AUDIT_2026-04-19 — companion to Flyway V39).
 *
 * <p><b>Gated</b>: only runs when {@code fivucsas.totp.migrate-on-boot=true}
 * (env: {@code FIVUCSAS_TOTP_MIGRATE_ON_BOOT}). Default OFF so boots during
 * normal operation do nothing.
 *
 * <p>Algorithm:
 * <ol>
 *   <li>Stream every row where {@code two_factor_secret IS NOT NULL}.</li>
 *   <li>If the stored value already starts with {@code enc:v1:}, skip.</li>
 *   <li>Otherwise treat as legacy plaintext and re-write the ciphertext form
 *       produced by {@link TotpSecretCipher#encrypt(String)}.</li>
 * </ol>
 *
 * <p>Runs outside the normal request flow; operators flip the flag during a
 * maintenance window.
 */
@Component
@ConditionalOnProperty(name = "fivucsas.totp.migrate-on-boot", havingValue = "true")
@RequiredArgsConstructor
@Slf4j
public class TotpSecretMigrator implements CommandLineRunner {

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final TotpSecretCipher cipher;

    @Override
    public void run(String... args) {
        log.warn("[TotpSecretMigrator] ENABLED — scanning users.two_factor_secret for legacy plaintext rows");
        AtomicInteger migrated = new AtomicInteger();
        AtomicInteger alreadyEncrypted = new AtomicInteger();
        AtomicInteger skipped = new AtomicInteger();

        jdbc.query(
                "SELECT id, two_factor_secret FROM users WHERE two_factor_secret IS NOT NULL",
                rs -> {
                    UUID id = (UUID) rs.getObject("id");
                    String stored = rs.getString("two_factor_secret");
                    if (stored == null || stored.isBlank()) {
                        skipped.incrementAndGet();
                        return;
                    }
                    if (cipher.isEncrypted(stored)) {
                        alreadyEncrypted.incrementAndGet();
                        return;
                    }
                    String ciphertext = cipher.encrypt(stored);
                    Integer rows = tx.execute(status -> jdbc.update(
                            "UPDATE users SET two_factor_secret = ? "
                                    + " WHERE id = ? AND two_factor_secret = ?",
                            ciphertext, id, stored));
                    if (rows != null && rows == 1) {
                        migrated.incrementAndGet();
                    } else {
                        // Row changed under us (concurrent write). Safe to skip —
                        // the writer wrote through the cipher already.
                        skipped.incrementAndGet();
                    }
                });

        log.warn("[TotpSecretMigrator] done: {} legacy rows re-encrypted, {} already encrypted, {} skipped",
                migrated.get(), alreadyEncrypted.get(), skipped.get());
        log.warn("[TotpSecretMigrator] Now set fivucsas.totp.migrate-on-boot=false and redeploy.");
    }
}
