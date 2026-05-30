package com.fivucsas.identity.db;

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

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for the V69 role/user_type unification migration.
 *
 * <p>Boots the full Flyway chain against a real Postgres so V69 runs end-to-end
 * (rename SUPER_ADMIN role → ROOT + the one-time, elevate-only tier sync). Verifies:
 * <ol>
 *   <li>The global SUPER_ADMIN role is renamed to ROOT, keeping its UUID + grants.</li>
 *   <li>A user holding the ROOT role ends up at {@code user_type='ROOT'}.</li>
 *   <li>A user holding a (per-tenant) TENANT_ADMIN role who was below TENANT_ADMIN
 *       is elevated to {@code user_type='TENANT_ADMIN'}.</li>
 *   <li>Elevate-only: a ROOT-typed user granted only a TENANT_ADMIN role is NOT
 *       demoted.</li>
 * </ol>
 *
 * <p>Gated on {@code RUN_INTEGRATION=true} (Testcontainers / self-hosted runner),
 * matching the project's split-CI convention. The seed + re-run of the V69 SQL is
 * idempotent, mirroring {@link IdentityBackfillIT}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("V69 role/user_type unification — rename + tier backfill")
class RoleUnificationBackfillIT {

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

    private static final UUID ROOT_ROLE_ID =
            UUID.fromString("10000000-0000-0000-0000-000000000001");

    @Test
    @DisplayName("Global SUPER_ADMIN role renamed to ROOT (UUID preserved, no SUPER_ADMIN left)")
    void superAdminRoleRenamedToRoot() {
        String name = jdbc.queryForObject(
                "SELECT name FROM roles WHERE id = ?", String.class, ROOT_ROLE_ID);
        assertThat(name).isEqualTo("ROOT");

        Long superAdminRows = jdbc.queryForObject(
                "SELECT COUNT(*) FROM roles WHERE name = 'SUPER_ADMIN'", Long.class);
        assertThat(superAdminRows).isZero();
    }

    @Test
    @Transactional
    @DisplayName("ROOT-role holder → user_type=ROOT; TENANT_ADMIN-role holder → ≥TENANT_ADMIN; no demote")
    void tierSyncElevatesByRole() {
        UUID tenant = seedTenant("v69-tenant");

        // (a) below-ROOT user granted the ROOT role → elevated to ROOT
        UUID rootUser = seedUser(tenant, "ROOT");        // wrong tier on purpose
        // start it BELOW root so the elevation is observable
        jdbc.update("UPDATE users SET user_type = 'TENANT_ADMIN' WHERE id = ?", rootUser);
        grantRole(rootUser, ROOT_ROLE_ID);

        // (b) TENANT_MEMBER granted a per-tenant TENANT_ADMIN role → TENANT_ADMIN
        UUID tenantAdminRoleId = seedTenantRole(tenant, "TENANT_ADMIN");
        UUID memberUser = seedUser(tenant, "TENANT_MEMBER");
        grantRole(memberUser, tenantAdminRoleId);

        // (c) ROOT-typed user granted ONLY a TENANT_ADMIN role → must NOT demote
        UUID alreadyRoot = seedUser(tenant, "ROOT");
        grantRole(alreadyRoot, tenantAdminRoleId);

        runV69TierSync();

        assertThat(userType(rootUser)).isEqualTo("ROOT");
        assertThat(userType(memberUser)).isEqualTo("TENANT_ADMIN");
        assertThat(userType(alreadyRoot)).isEqualTo("ROOT"); // elevate-only: no demotion
    }

    // ---- helpers ----

    private String userType(UUID userId) {
        return jdbc.queryForObject("SELECT user_type FROM users WHERE id = ?", String.class, userId);
    }

    private UUID seedTenant(String name) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO tenants (id, name, domain, display_name, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, true, NOW(), NOW())",
                id, name + "-" + id, name + "-" + id + ".test", name);
        return id;
    }

    private UUID seedUser(UUID tenantId, String userType) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, " +
                "user_type, status, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "'T', 'U', ?, 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, "u-" + id + "@example.com", userType);
        return id;
    }

    private UUID seedTenantRole(UUID tenantId, String name) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO roles (id, tenant_id, name, description, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, true, NOW(), NOW())",
                id, tenantId, name, name + " role");
        return id;
    }

    private void grantRole(UUID userId, UUID roleId) {
        jdbc.update(
                "INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, NOW()) " +
                "ON CONFLICT DO NOTHING",
                userId, roleId);
    }

    /** The V69 tier-sync SQL (kept in sync with the migration). Idempotent / elevate-only. */
    private void runV69TierSync() {
        jdbc.update(
                "UPDATE users u SET user_type = 'ROOT', updated_at = CURRENT_TIMESTAMP " +
                "WHERE u.user_type <> 'ROOT' AND EXISTS (" +
                "  SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id " +
                "    AND ur.role_id = '10000000-0000-0000-0000-000000000001')");
        jdbc.update(
                "UPDATE users u SET user_type = 'TENANT_ADMIN', updated_at = CURRENT_TIMESTAMP " +
                "WHERE u.user_type IN ('TENANT_MEMBER','GUEST') AND EXISTS (" +
                "  SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id " +
                "    WHERE ur.user_id = u.id AND r.name = 'TENANT_ADMIN' AND r.is_active = TRUE)");
    }
}
