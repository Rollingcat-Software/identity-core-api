package com.fivucsas.identity.integration;

import com.fivucsas.identity.application.port.output.AuthorTrialStorePort;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Finish;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.NewAttempt;
import com.fivucsas.identity.application.port.output.AuthorTrialStorePort.Verdicts;
import com.fivucsas.identity.controller.AuthorTrialController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End to end through Flyway V90 + the real JPA adapter + the export endpoint:
 * a trial attempt is planned, recorded (verdicts + authoritative accept) and
 * exported in the documented CSV schema, with its device/environment JSONB kept
 * as real objects. No biometric service, Redis or user login is involved.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
class AuthorTrialStoreIntegrationTest {

    private static final UUID TENANT =
            UUID.fromString("c0c0c0c0-1111-2222-3333-444444444444");
    private static final UUID USER =
            UUID.fromString("c0c0c0c0-5555-6666-7777-888888888888");
    private static final String KEY = "integration-secret";

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("app.author-trial.enabled", () -> "true");
        registry.add("app.author-trial.access-code", () -> KEY);
        registry.add("app.author-trial.tenant-ids", TENANT::toString);
        registry.add("app.author-trial.api-version", () -> "it-api");
        registry.add("app.author-trial.fallback-bio-version", () -> "it-bio");
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private AuthorTrialStorePort store;

    @BeforeEach
    void clean() {
        jdbc.update("DELETE FROM author_trial_attempts WHERE tenant_id = ?", TENANT);
        jdbc.update("DELETE FROM author_trial_plan_entries WHERE tenant_id = ?", TENANT);
        jdbc.update("DELETE FROM author_trial_participants WHERE tenant_id = ?", TENANT);
        jdbc.update("""
                INSERT INTO author_trial_participants
                    (id, tenant_id, participant_code, user_id, enrolled_at, created_at)
                VALUES (?, ?, 'P1', ?, NOW(), NOW())
                """, UUID.randomUUID(), TENANT, USER);
    }

    @Test
    void attemptIsRecordedAndExportedInTheDocumentedSchema() throws Exception {
        UUID attemptId = store.createAttempt(new NewAttempt(TENANT, "P1", "genuine", "P1",
                null, null, "blink", "blink", 1, 1, null, true, "easy", 1, "audit",
                UUID.randomUUID(), Instant.now(), "{\"label\":\"IT laptop\"}",
                "{\"brightness\":0.5,\"localTimeOfDay\":\"21:14\"}", "it-web", "it-api", "it-bio"));

        store.recordVerdicts(UUID.fromString(jdbc.queryForObject(
                        "SELECT mfa_session_id::text FROM author_trial_attempts WHERE id = ?",
                        String.class, attemptId)),
                new Verdicts("pass", "pass", "pass", null, 0.71, 0.29, 0.4, Instant.now()));
        // The authoritative accept normally comes from VerifyMfaStepService.completeMfa.
        UUID mfa = UUID.fromString(jdbc.queryForObject(
                "SELECT mfa_session_id::text FROM author_trial_attempts WHERE id = ?",
                String.class, attemptId));
        store.recordAccept(mfa, Instant.now());

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT outcome, liveness_verdict, identity_verdict, identity_score, "
                        + "jsonb_typeof(device_json) AS device_type, "
                        + "jsonb_typeof(env_json) AS env_type "
                        + "FROM author_trial_attempts WHERE id = ?", attemptId);
        assertThat(row.get("outcome")).isEqualTo("accept");
        assertThat(row.get("liveness_verdict")).isEqualTo("pass");
        assertThat(row.get("identity_verdict")).isEqualTo("pass");
        assertThat(((Number) row.get("identity_score")).doubleValue()).isEqualTo(0.71);
        assertThat(row.get("device_type")).isEqualTo("object");
        assertThat(row.get("env_type")).isEqualTo("object");

        MvcResult res = mockMvc.perform(get("/api/v1/author-trial/export")
                        .param("format", "csv")
                        .header(AuthorTrialController.KEY_HEADER, KEY))
                .andExpect(status().isOk())
                .andReturn();
        String csv = res.getResponse().getContentAsString();
        String[] lines = csv.split("\n");
        assertThat(lines[0]).startsWith("date,participant,operator,session_no,condition");
        assertThat(lines[0]).endsWith("attempt_id");
        assertThat(lines[1]).contains(",P1,P1,1,bona_fide,none,");
        assertThat(lines[1]).contains(",accept,pass,pass,");
        assertThat(lines[1]).contains("IT laptop");
        assertThat(lines[1]).contains(",moderate,");
        assertThat(lines[1]).contains(attemptId.toString());
    }

    @Test
    void exportWithoutTheKeyIsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/author-trial/export").param("format", "csv"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void finishCannotUpgradeAPendingAttemptToAccept() throws Exception {
        UUID attemptId = store.createAttempt(new NewAttempt(TENANT, "P1", "genuine", "P1",
                null, null, "blink", "blink", 1, 1, null, true, "easy", 1, "audit",
                UUID.randomUUID(), Instant.now(), null, null, null, "it-api", "it-bio"));
        store.recordFinish(attemptId, new Finish("accepted", null, 10, null, null, Instant.now()));
        Map<String, Object> row = jdbc.queryForMap(
                "SELECT outcome, failure_reason FROM author_trial_attempts WHERE id = ?", attemptId);
        assertThat(row.get("outcome")).isEqualTo("reject");
        assertThat(row.get("failure_reason")).isEqualTo("server_did_not_authenticate");
    }

    @Test
    void planSlotsAreUniquePerRoundAndPosition() {
        store.createRound(TENANT, "P1", "genuine", 1, List.of("blink", "smile"));
        store.createRound(TENANT, "P1", "genuine", 2, List.of("smile", "blink"));
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM author_trial_plan_entries WHERE tenant_id = ?",
                Integer.class, TENANT)).isEqualTo(4);
    }

    @Test
    void purgeDeletesTheTrialRowsForTheTenant() {
        store.createRound(TENANT, "P1", "genuine", 1, List.of("blink"));
        AuthorTrialStorePort.DeletionCounts counts = store.deleteForTenant(TENANT);
        assertThat(counts.participants()).isEqualTo(1);
        assertThat(counts.planEntries()).isEqualTo(1);
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM author_trial_participants WHERE tenant_id = ?",
                Integer.class, TENANT)).isZero();
    }
}