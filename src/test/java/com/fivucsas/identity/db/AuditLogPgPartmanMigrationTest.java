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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test for V57 — pg_partman-managed audit_logs partitioning.
 *
 * <p>The vanilla {@code postgres:16-alpine} image does not bundle
 * {@code pg_partman}. V57 is intentionally fail-soft in that case: it logs a
 * WARNING and exits cleanly so Flyway / api boot are not blocked. This test
 * exercises that path.
 *
 * <p>To exercise the happy path (extension installed, parent registered,
 * cron scheduled), run against a postgres image that bundles
 * {@code postgresql-16-partman} and {@code postgresql-16-cron} — see
 * {@code RUNBOOK_AUDIT_LOG_PARTMAN.md} Option A. That variant is omitted from
 * CI because the runner does not have the custom image; it can be exercised
 * in a maintenance-window integration job.
 *
 * <p>Gated behind {@code RUN_INTEGRATION=true}, matching the other
 * Testcontainers tests in this project.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("V57 pg_partman migration is fail-soft on vanilla postgres")
class AuditLogPgPartmanMigrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_v57_test")
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
    @DisplayName("Flyway boots successfully even though pg_partman is absent")
    void flyway_appliesV57_evenWithoutPartman() {
        // V57 should be recorded as success in flyway_schema_history.
        Integer count = jdbc.queryForObject(
                "SELECT count(*) FROM flyway_schema_history " +
                "WHERE version = '57' AND success = TRUE",
                Integer.class);
        assertThat(count)
                .as("V57 should appear as successful in flyway_schema_history "
                        + "(migration is fail-soft when pg_partman is unavailable)")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("audit_logs table still exists and is queryable post-migration")
    void auditLogs_stillUsable() {
        // Whether V40 ran (partitioned) or not (heap), V57 must not damage the
        // table. Either relkind is acceptable here.
        String relkind = jdbc.queryForObject(
                "SELECT relkind::text FROM pg_class " +
                "WHERE relname = 'audit_logs' AND relnamespace = 'public'::regnamespace",
                String.class);
        assertThat(relkind)
                .as("audit_logs must survive V57 as either heap (r) or partitioned (p)")
                .isIn("r", "p");
    }

    @Test
    @DisplayName("partman extension is NOT created when unavailable (fail-soft)")
    void partmanExtension_isNotCreated() {
        Integer extCount = jdbc.queryForObject(
                "SELECT count(*) FROM pg_extension WHERE extname = 'pg_partman'",
                Integer.class);
        assertThat(extCount)
                .as("V57 must not create pg_partman extension on a server that lacks it")
                .isEqualTo(0);
    }
}
