package com.fivucsas.identity.integration;

import com.fivucsas.identity.application.service.SoftDeletePurgeJob;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * F9 — ShedLock single-replica path test for {@link SoftDeletePurgeJob}.
 *
 * <p>Validates V51 + {@code @SchedulerLock} on {@code runScheduled()}: two
 * concurrent calls must produce exactly one purge cycle. Also exercises the
 * V53 BEFORE-DELETE trigger bypass inside {@link SoftDeletePurgeJob#purgeBatch}
 * (a missing {@code SET LOCAL app.allow_hard_delete='on'} would surface as
 * {@code purged == 0} on the second test).</p>
 */
@SpringBootTest
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@TestPropertySource(properties = {
        "app.purge.softDelete.enabled=true"   // unlock the job for the duration of the test
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@DisplayName("F9 — SoftDeletePurgeJob ShedLock concurrency")
class SoftDeletePurgeJobConcurrencyTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_f9_test")
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
    private SoftDeletePurgeJob purgeJob;

    @Autowired
    private JdbcTemplate jdbc;

    private UUID tenantId;
    private UUID alice;
    private UUID bob;

    @BeforeEach
    void seed() {
        // Defensive cleanup so the test is idempotent if a previous run crashed.
        jdbc.update("DELETE FROM shedlock WHERE name LIKE 'SoftDelete%'");
        ReflectionTestUtils.setField(purgeJob, "enabled", true);

        tenantId = seedTenant();
        alice = seedSoftDeletedUser(tenantId, "alice-f9@example.com",
                Instant.now().minus(45, ChronoUnit.DAYS));
        bob   = seedSoftDeletedUser(tenantId, "bob-f9@example.com",
                Instant.now().minus(45, ChronoUnit.DAYS));
    }

    @AfterEach
    void cleanup() {
        // SoftDeletePurgeJob.purgeBatch sets app.allow_hard_delete; do likewise here for cleanup.
        jdbc.execute("BEGIN");
        try {
            jdbc.execute("SET LOCAL app.allow_hard_delete = 'on'");
            jdbc.update("DELETE FROM users WHERE id IN (?, ?)", alice, bob);
            jdbc.execute("COMMIT");
        } catch (RuntimeException e) {
            jdbc.execute("ROLLBACK");
        }
        jdbc.update("UPDATE tenants SET deleted_at = NOW() WHERE id = ? AND deleted_at IS NULL",
                tenantId);
        jdbc.update("DELETE FROM shedlock WHERE name LIKE 'SoftDelete%'");
    }

    @Test
    @DisplayName("two concurrent runScheduled() calls — exactly one purges, the other is a no-op")
    void concurrentRunScheduled_onlyOneAcquiresLock() throws Exception {
        AtomicInteger errors = new AtomicInteger();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done  = new CountDownLatch(2);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        for (int i = 0; i < 2; i++) {
            pool.submit(() -> {
                try {
                    ready.countDown();
                    start.await();
                    purgeJob.runScheduled();
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }

        ready.await(5, TimeUnit.SECONDS);
        start.countDown();   // unleash both threads
        done.await(60, TimeUnit.SECONDS);
        pool.shutdownNow();

        // Both threads completed without throwing — ShedLock contention is silent (no-op for the loser).
        assertThat(errors.get()).isZero();

        // Both seeded users were purged exactly once (NOT double-processed).
        Integer remaining = jdbc.queryForObject(
                "SELECT count(*) FROM users WHERE id IN (?, ?)", Integer.class, alice, bob);
        assertThat(remaining)
                .as("Expected both seeded users purged by the lock-holder")
                .isZero();

        // Audit log emitted exactly once per purged user (no doubles from the no-op caller).
        // AuditLogAdapter.logSecurityEvent persists action='USER_HARD_PURGED' with the
        // user-id substring inside the JSONB metadata.details key.
        Integer auditCount = jdbc.queryForObject(
                "SELECT count(*) FROM audit_logs " +
                "WHERE action = 'USER_HARD_PURGED' " +
                "AND (metadata->>'details' LIKE ? OR metadata->>'details' LIKE ?)",
                Integer.class,
                "%" + alice + "%", "%" + bob + "%");
        assertThat(auditCount)
                .as("Each user purged once — no double-emit from the lock loser")
                .isEqualTo(2);

        // ShedLock row was actually written — proves the lock provider is wired.
        List<String> lockNames = jdbc.queryForList(
                "SELECT name FROM shedlock WHERE name LIKE 'SoftDelete%'", String.class);
        assertThat(lockNames).contains("SoftDeletePurgeJob_runScheduled");
    }

    @Test
    @DisplayName("V53 BEFORE-DELETE trigger bypass active inside purgeBatch — hard-delete succeeds")
    void hardDeleteBypass_isHonoredInsidePurgeBatch() {
        // Sanity-check the bypass: invoke purge() directly (no contention) and assert
        // both users are gone. If purgeBatch forgets the SET LOCAL, V53 raises restrict_violation
        // and the per-user catch logs an error, leaving rows in place.
        SoftDeletePurgeJob.PurgeResult result = purgeJob.purge();

        assertThat(result.purged()).isEqualTo(2);
        assertThat(result.purgedIds()).containsExactlyInAnyOrder(alice, bob);

        Integer remaining = jdbc.queryForObject(
                "SELECT count(*) FROM users WHERE id IN (?, ?)", Integer.class, alice, bob);
        assertThat(remaining).isZero();
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private UUID seedTenant() {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, contact_email, status, max_users, " +
                "biometric_enabled, session_timeout_minutes, refresh_token_validity_days, " +
                "is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, 'ACTIVE', 100, true, 30, 7, true, NOW(), NOW())",
                id, "F9 tenant " + id, "f9-" + id, "f9-" + id + "@example.com");
        return id;
    }

    private UUID seedSoftDeletedUser(UUID tenantId, String email, Instant deletedAt) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, " +
                "status, is_active, created_at, updated_at, deleted_at) " +
                "VALUES (?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "'F9', 'Test', 'INACTIVE', false, NOW(), NOW(), ?)",
                id, tenantId, email, java.sql.Timestamp.from(deletedAt));
        return id;
    }
}
