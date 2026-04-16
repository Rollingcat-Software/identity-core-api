package com.fivucsas.identity.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security filter-chain integration test for anonymous OAuth2 endpoints used by the
 * hosted-login flow.
 *
 * <p>Unlike {@link com.fivucsas.identity.controller.OAuth2ControllerTest}, which
 * uses {@code @AutoConfigureMockMvc(addFilters = false)} and therefore bypasses the
 * real {@code SecurityFilterChain}, this test runs the whole {@code @SpringBootTest}
 * context with security filters enabled. It catches cases where a public endpoint
 * is shadowed by a later {@code .authenticated()} rule in {@link
 * com.fivucsas.identity.config.SecurityConfig} — a class of bug that WebMvcTest-only
 * coverage silently misses.
 *
 * <p>The assertion is intentionally permissive: we only check the response is not
 * {@code 401 Unauthorized}. A 404 (unknown client), 400 (validation error), or 200
 * (success) all indicate the request reached the controller.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("integration")
@DisplayName("OAuth2 public endpoints reach controller through real SecurityFilterChain")
class OAuth2PublicEndpointsSecurityIntegrationTest {

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

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("GET /oauth2/clients/{id}/public — anonymous request is NOT 401")
    void clientPublicMeta_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/api/v1/oauth2/clients/test-client/public"))
                // The client doesn't exist → 404 is correct. 401 would mean SecurityConfig
                // is blocking the endpoint before the controller runs.
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("POST /oauth2/authorize/complete — anonymous request is NOT 401")
    void authorizeComplete_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/oauth2/authorize/complete")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                // Missing fields → 400 invalid_request. 401 would mean the filter chain
                // rejected the anonymous caller before the controller.
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("GET /oauth2/authorize — anonymous request is NOT 401")
    void authorize_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/api/v1/oauth2/authorize")
                        .param("client_id", "anon-test")
                        .param("redirect_uri", "https://example.com/cb")
                        .param("response_type", "code"))
                .andExpect(status().is(not(equalTo(401))));
    }
}
