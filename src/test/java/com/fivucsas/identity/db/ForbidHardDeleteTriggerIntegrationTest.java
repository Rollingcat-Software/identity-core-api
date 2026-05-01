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
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration test for V53 — BEFORE DELETE triggers on users + tenants.
 *
 * <p>Background: 2026-04-28 incident — a hard {@code DELETE FROM users}
 * cascaded across ~13 child tables. V53 installs
 * {@code tg_users_forbid_hard_delete} and {@code tg_tenants_forbid_hard_delete}
 * to block raw deletes at the engine level, with a session-local GUC bypass
 * ({@code app.allow_hard_delete = 'on'}) for the legitimate
 * {@code SoftDeletePurgeJob}.
 *
 * <p>Gated behind {@code RUN_INTEGRATION=true} like the other Testcontainers
 * tests in this project — CI runs a Postgres 16 container; local dev does not.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("V53 forbid_hard_delete trigger integration test")
class ForbidHardDeleteTriggerIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_v53_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("Both BEFORE DELETE triggers exist after Flyway migrates")
    void triggers_areInstalled() {
        Integer userTrigger = jdbc.queryForObject(
                "SELECT count(*) FROM information_schema.triggers " +
                "WHERE trigger_name = 'tg_users_forbid_hard_delete' " +
                "AND event_object_table = 'users' AND action_timing = 'BEFORE'",
                Integer.class);
        assertThat(userTrigger).isEqualTo(1);

        Integer tenantTrigger = jdbc.queryForObject(
                "SELECT count(*) FROM information_schema.triggers " +
                "WHERE trigger_name = 'tg_tenants_forbid_hard_delete' " +
                "AND event_object_table = 'tenants' AND action_timing = 'BEFORE'",
                Integer.class);
        assertThat(tenantTrigger).isEqualTo(1);
    }

    @Test
    @DisplayName("Hard DELETE FROM users raises restrict_violation")
    void hardDeleteUsers_isBlocked() {
        UUID tenantId = seedTenant();
        UUID userId = seedUser(tenantId, "blocked-delete@example.com");

        assertThatThrownBy(() ->
                jdbc.update("DELETE FROM users WHERE id = ?", userId))
                .hasMessageContaining("Hard DELETE forbidden on users")
                .hasMessageContaining("soft-delete");

        // Row still exists.
        Integer count = jdbc.queryForObject(
                "SELECT count(*) FROM users WHERE id = ?", Integer.class, userId);
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("Hard DELETE FROM tenants raises restrict_violation")
    void hardDeleteTenants_isBlocked() {
        UUID tenantId = seedTenant();

        assertThatThrownBy(() ->
                jdbc.update("DELETE FROM tenants WHERE id = ?", tenantId))
                .hasMessageContaining("Hard DELETE forbidden on tenants");

        Integer count = jdbc.queryForObject(
                "SELECT count(*) FROM tenants WHERE id = ?", Integer.class, tenantId);
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("Setting app.allow_hard_delete='on' bypasses the trigger inside one TX")
    void bypassGuc_allowsLegitimatePurge() {
        UUID tenantId = seedTenant();
        UUID userId = seedUser(tenantId, "purge-allowed@example.com");

        // Single TX: SET LOCAL + DELETE — emulates SoftDeletePurgeJob.purgeBatch().
        jdbc.execute((java.sql.Connection conn) -> {
            boolean prevAuto = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try (java.sql.Statement st = conn.createStatement()) {
                st.execute("SET LOCAL app.allow_hard_delete = 'on'");
                int rows;
                try (java.sql.PreparedStatement ps = conn.prepareStatement(
                        "DELETE FROM users WHERE id = ?")) {
                    ps.setObject(1, userId);
                    rows = ps.executeUpdate();
                }
                conn.commit();
                return rows;
            } finally {
                conn.setAutoCommit(prevAuto);
            }
        });

        Integer count = jdbc.queryForObject(
                "SELECT count(*) FROM users WHERE id = ?", Integer.class, userId);
        assertThat(count).isZero();
    }

    private UUID seedTenant() {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO tenants (id, name, is_active, created_at, updated_at) " +
                "VALUES (?, ?, true, NOW(), NOW())",
                id, "v53-test-" + id);
        return id;
    }

    private UUID seedUser(UUID tenantId, String email) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, " +
                "status, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "'V53', 'Test', 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, email);
        return id;
    }
}
