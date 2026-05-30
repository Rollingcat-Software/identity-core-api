package com.fivucsas.identity.db;

import com.fivucsas.identity.entity.Identity;
import com.fivucsas.identity.entity.IdentityEmail;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.IdentityEmailRepository;
import com.fivucsas.identity.repository.IdentityRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the Phase 1 identity layer (V65–V67).
 *
 * <p>Boots the full Flyway migration chain against a real Postgres so V67's
 * PL/pgSQL backfill runs end-to-end. Verifies:
 * <ol>
 *   <li>The V67 RAISE-EXCEPTION guard left 0 users with NULL identity_id (the
 *       migration would have aborted otherwise, so reaching boot already proves
 *       it; we assert explicitly for documentation).</li>
 *   <li>Every users row's {@code email} has a matching verified {@code identity_emails}
 *       row and a non-null {@code identity_id}.</li>
 *   <li>Two users sharing an email across tenants resolve to the SAME identity
 *       (the cross-tenant pre-link rule + the case-insensitive UNIQUE).</li>
 *   <li>The {@link Identity}/{@link IdentityEmail} repos persist + read, the
 *       {@code User.identity} mapping loads, and the raw {@code identityId}
 *       column reads.</li>
 * </ol>
 *
 * <p>Gated on {@code RUN_INTEGRATION=true} (Testcontainers / self-hosted runner),
 * matching the project's split-CI convention.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Identity layer V65–V67 — backfill + repositories")
class IdentityBackfillIT {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_identity_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    @Autowired private JdbcTemplate jdbc;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private IdentityEmailRepository identityEmailRepository;
    @Autowired private UserRepository userRepository;

    @Test
    @DisplayName("V67 left zero users with NULL identity_id (raw, incl. soft-deleted)")
    void backfillLeavesNoNullIdentityId() {
        Long nullCount = jdbc.queryForObject(
                "SELECT COUNT(*) FROM users WHERE identity_id IS NULL", Long.class);
        assertThat(nullCount).isZero();
    }

    @Test
    @DisplayName("Every users.email has a verified identity_emails row")
    void everyUserEmailHasVerifiedIdentityEmail() {
        Long orphanUsers = jdbc.queryForObject(
                "SELECT COUNT(*) FROM users u " +
                "WHERE NOT EXISTS (SELECT 1 FROM identity_emails ie " +
                "                  WHERE lower(ie.email) = lower(u.email) AND ie.verified = true)",
                Long.class);
        assertThat(orphanUsers).isZero();

        // identity_emails are globally unique on lower(email)
        Long dupEmails = jdbc.queryForObject(
                "SELECT COUNT(*) FROM (" +
                "  SELECT lower(email) FROM identity_emails GROUP BY lower(email) HAVING COUNT(*) > 1" +
                ") d", Long.class);
        assertThat(dupEmails).isZero();
    }

    @Test
    @Transactional
    @DisplayName("Two users sharing an email across tenants share ONE identity")
    void sameEmailAcrossTenantsLinksToSameIdentity() {
        // Seed two tenants + two users with the SAME email, then run the V67
        // backfill SQL again (idempotent) so the new rows are linked.
        UUID tenantA = seedTenant("backfill-tenant-a");
        UUID tenantB = seedTenant("backfill-tenant-b");
        String sharedEmail = "shared-" + UUID.randomUUID() + "@example.com";

        UUID userA = seedUser(tenantA, sharedEmail, "Shared", "PersonA");
        UUID userB = seedUser(tenantB, sharedEmail, "Shared", "PersonB");

        runBackfill();

        UUID identityA = jdbc.queryForObject(
                "SELECT identity_id FROM users WHERE id = ?", UUID.class, userA);
        UUID identityB = jdbc.queryForObject(
                "SELECT identity_id FROM users WHERE id = ?", UUID.class, userB);

        assertThat(identityA).isNotNull();
        assertThat(identityB).isEqualTo(identityA);

        // exactly ONE identity_emails row anchors the shared address
        Long emailRows = jdbc.queryForObject(
                "SELECT COUNT(*) FROM identity_emails WHERE lower(email) = lower(?)",
                Long.class, sharedEmail);
        assertThat(emailRows).isEqualTo(1L);
    }

    @Test
    @Transactional
    @DisplayName("Identity + IdentityEmail persist via repos; User.identity + raw id load")
    void repositoriesPersistAndUserMappingLoads() {
        Identity identity = identityRepository.saveAndFlush(
                Identity.builder().displayName("Repo Person").build());
        assertThat(identity.getId()).isNotNull();
        assertThat(identity.getStatus()).isEqualTo("ACTIVE");

        String email = "repo-" + UUID.randomUUID() + "@example.com";
        IdentityEmail saved = identityEmailRepository.saveAndFlush(
                IdentityEmail.builder()
                        .identity(identity)
                        .email(email)
                        .verified(true)
                        .verifiedAt(java.time.Instant.now())
                        .build());
        assertThat(saved.getId()).isNotNull();

        Optional<IdentityEmail> byEmail = identityEmailRepository.findByEmailIgnoreCase(email.toUpperCase());
        assertThat(byEmail).isPresent();
        assertThat(byEmail.get().getIdentityId()).isEqualTo(identity.getId());

        List<IdentityEmail> byIdentity = identityEmailRepository.findByIdentityId(identity.getId());
        assertThat(byIdentity).extracting(IdentityEmail::getId).contains(saved.getId());

        // Link a user to the identity and re-read; mapping + raw column both load.
        UUID tenant = seedTenant("repo-tenant");
        UUID userId = seedUser(tenant, "repo-user-" + UUID.randomUUID() + "@example.com", "Repo", "User");
        jdbc.update("UPDATE users SET identity_id = ? WHERE id = ?", identity.getId(), userId);

        User reloaded = userRepository.findById(userId).orElseThrow();
        assertThat(reloaded.getIdentityId()).isEqualTo(identity.getId());
        assertThat(reloaded.getIdentity().getId()).isEqualTo(identity.getId());
    }

    // ---- helpers (raw SQL, mirroring CrossTenantIsolationIT) ----

    private UUID seedTenant(String name) {
        UUID id = UUID.randomUUID();
        // slug is NOT NULL since V20 — the fixture must supply it (unique per row).
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, domain, display_name, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, ?, true, NOW(), NOW())",
                id, name + "-" + id, name + "-" + id, name + "-" + id + ".test", name);
        return id;
    }

    private UUID seedUser(UUID tenantId, String email, String first, String last) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, " +
                "user_type, status, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "?, ?, 'TENANT_MEMBER', 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, email, first, last);
        return id;
    }

    /**
     * The exact V67 backfill loop (kept in sync with the migration). Idempotent:
     * only touches users with NULL identity_id and only creates an identity/email
     * when none exists for that lower(email).
     */
    private void runBackfill() {
        jdbc.execute(
            "DO $$ " +
            "DECLARE rec RECORD; v_identity_id UUID; v_display_name TEXT; " +
            "BEGIN " +
            "  FOR rec IN SELECT lower(email) AS norm_email FROM users " +
            "             WHERE identity_id IS NULL GROUP BY lower(email) LOOP " +
            "    SELECT ie.identity_id INTO v_identity_id FROM identity_emails ie " +
            "      WHERE lower(ie.email) = rec.norm_email LIMIT 1; " +
            "    IF v_identity_id IS NULL THEN " +
            "      SELECT NULLIF(btrim(concat_ws(' ', u.first_name, u.last_name)), '') " +
            "        INTO v_display_name FROM users u WHERE lower(u.email) = rec.norm_email " +
            "        ORDER BY u.created_at LIMIT 1; " +
            "      INSERT INTO identities (display_name, status, created_at, updated_at) " +
            "        VALUES (v_display_name, 'ACTIVE', now(), now()) RETURNING id INTO v_identity_id; " +
            "      INSERT INTO identity_emails (identity_id, email, verified, verified_at, created_at) " +
            "        SELECT v_identity_id, u.email, true, now(), now() FROM users u " +
            "        WHERE lower(u.email) = rec.norm_email ORDER BY u.created_at LIMIT 1; " +
            "    END IF; " +
            "    UPDATE users SET identity_id = v_identity_id " +
            "      WHERE lower(email) = rec.norm_email AND identity_id IS NULL; " +
            "  END LOOP; " +
            "END $$;");
    }
}
