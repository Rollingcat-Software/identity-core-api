package com.fivucsas.identity.integration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End to end through the real filter chain and Flyway V89: an anonymous visitor can
 * store a run (and the jsonb payload is a real object, not a double-encoded string),
 * but cannot read anything back.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
class DevbenchRunsIntegrationTest {

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
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbc;

    @Test
    void submit_WhenAnonymous_ShouldStoreSanitisedJsonbRow() throws Exception {
        String body = "{\"tool\":\"fivucsas devbench app v1\",\"batchId\":\"it1\",\"runIndex\":1,"
                + "\"participant\":\"Ayse\",\"uid\":\"secret\",\"deviceKey\":\"sm-a145f\","
                + "\"timingsMs\":{\"warm\":{\"p50\":101.5}}}";

        MvcResult res = mockMvc.perform(post("/api/v1/devbench/runs")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated())
                .andReturn();

        String id = res.getResponse().getContentAsString().replaceAll(".*\"id\":\"([^\"]+)\".*", "$1");
        Map<String, Object> row = jdbc.queryForMap(
                "SELECT jsonb_typeof(payload) AS t, payload->>'participant' AS name, jsonb_exists(payload, 'uid') AS has_uid, "
                        + "(payload->'timingsMs'->'warm'->>'p50')::numeric AS p50, device_key "
                        + "FROM devbench_runs WHERE id = ?", UUID.fromString(id));
        assertThat(row.get("t")).isEqualTo("object");
        assertThat(row.get("name")).isEqualTo("Ayse");
        assertThat(row.get("has_uid")).isEqualTo(false);
        assertThat(row.get("p50").toString()).isEqualTo("101.5");
        assertThat(row.get("device_key")).isEqualTo("sm-a145f");
    }

    @Test
    void export_WhenAnonymous_ShouldBeUnauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/admin/devbench/runs"))
                .andExpect(status().isUnauthorized());
    }
}
