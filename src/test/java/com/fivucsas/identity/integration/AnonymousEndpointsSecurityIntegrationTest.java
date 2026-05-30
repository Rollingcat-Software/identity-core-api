package com.fivucsas.identity.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Sibling of {@link OAuth2PublicEndpointsSecurityIntegrationTest}: drives the
 * full {@code @SpringBootTest} security filter chain against the OTHER
 * anonymous endpoints declared in
 * {@link com.fivucsas.identity.config.SecurityConfig#securityFilterChain},
 * so that the F6 dispatch dossier
 * (controller slice tests with {@code @AutoConfigureMockMvc(addFilters=false)}
 * silently bypass SecurityConfig) is closed at runtime.
 *
 * <p>{@link com.fivucsas.identity.config.SecurityConfigPermitAllPinTest} closes
 * the same gap at unit-test time via source-level pinning. This test catches
 * the cases where the source string is preserved but the matcher order or
 * predicate semantics regress (e.g. a downstream {@code .authenticated()}
 * shadows an earlier {@code .permitAll()}).
 *
 * <p>Assertions are intentionally permissive: we only check the response is
 * NOT 401. A 400 / 404 / 405 / 200 all indicate the request reached the
 * controller layer through the real filter chain.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Anonymous-endpoint reachability through real SecurityFilterChain")
class AnonymousEndpointsSecurityIntegrationTest {

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

    // ── /api/v1/auth/* permitAll ─────────────────────────────────────────

    @Test
    @DisplayName("POST /auth/login — anonymous request is NOT 401")
    void login_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("POST /auth/refresh — anonymous request is NOT 401")
    void refresh_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"\"}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("GET /auth/health — anonymous request is NOT 401")
    void authHealth_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/health"))
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("POST /auth/forgot-password — anonymous request is NOT 401")
    void forgotPassword_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nobody@example.com\"}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── N-step MFA permitAll (pre-JWT, session-token authn) ──────────────

    @Test
    @DisplayName("POST /auth/mfa/step — anonymous request is NOT 401")
    void mfaStep_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/mfa/step")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── Auth-session multi-step pre-JWT permitAll ───────────────────────

    @Test
    @DisplayName("POST /auth/sessions — anonymous request is NOT 401")
    void authSessionsCreate_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/sessions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("GET /auth/sessions/{id} — anonymous request is NOT 401")
    void authSessionsGet_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── Auth-session DELETE — MUST be 401 (post-audit 2026-04-24 #3) ─────

    @Test
    @DisplayName("DELETE /auth/sessions/{id} — anonymous request IS 401 (regression guard)")
    void authSessionsDelete_Anonymous_ShouldBe401() throws Exception {
        // The opposite assertion vs the others: we WANT 401 so an attacker
        // can't enumerate-cancel arbitrary sessions by id.
        mockMvc.perform(delete("/api/v1/auth/sessions/00000000-0000-0000-0000-000000000000"))
                .andExpect(status().isUnauthorized());
    }

    // ── QR session permitAll ─────────────────────────────────────────────

    @Test
    @DisplayName("POST /auth/qr/session — anonymous request is NOT 401")
    void qrSessionCreate_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/qr/session")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── Approve-login (number-matching) permitAll initiator side ─────────

    @Test
    @DisplayName("POST /auth/approve-login/session — anonymous request is NOT 401")
    void approveLoginCreate_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/approve-login/session")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"nobody@example.com\"}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("GET /auth/approve-login/session/{id} — anonymous poll is NOT 401")
    void approveLoginPoll_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/approve-login/session/00000000-0000-0000-0000-000000000000"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── Approve-login approver side — MUST be 401 anonymous ──────────────

    @Test
    @DisplayName("GET /auth/approve-login/pending — anonymous request IS 401 (approver-only)")
    void approveLoginPending_Anonymous_ShouldBe401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/approve-login/pending"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /auth/approve-login/session/{id}/decide — anonymous request IS 401 (approver-only)")
    void approveLoginDecide_Anonymous_ShouldBe401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/approve-login/session/00000000-0000-0000-0000-000000000000/decide")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"decision\":\"deny\"}"))
                .andExpect(status().isUnauthorized());
    }

    // ── Usernameless / discoverable passkey pre-login permitAll (Phase 1) ─

    @Test
    @DisplayName("POST /webauthn/passkey/authenticate-options — anonymous request is NOT 401")
    void passkeyAuthenticateOptions_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/webauthn/passkey/authenticate-options")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("POST /webauthn/passkey/authenticate — anonymous request is NOT 401")
    void passkeyAuthenticate_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/webauthn/passkey/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── WebAuthn pre-login permitAll ─────────────────────────────────────

    @Test
    @DisplayName("POST /webauthn/authenticate-options — anonymous request is NOT 401")
    void webauthnAuthenticateOptions_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(post("/api/v1/webauthn/authenticate-options")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── Public auth-method listing permitAll ─────────────────────────────

    @Test
    @DisplayName("GET /auth-methods — anonymous request is NOT 401")
    void authMethods_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/api/v1/auth-methods"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── /actuator/health permitAll, /actuator/* not (in prod) ────────────

    @Test
    @DisplayName("GET /actuator/health — anonymous request is NOT 401")
    void actuatorHealth_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── OIDC discovery + JWKS permitAll ──────────────────────────────────

    @Test
    @DisplayName("GET /.well-known/openid-configuration — anonymous request is NOT 401")
    void openidConfig_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().is(not(equalTo(401))));
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json — anonymous request is NOT 401")
    void jwks_Anonymous_ShouldNotBe401() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().is(not(equalTo(401))));
    }

    // ── Authenticated catch-all: /api/v1/users/me MUST be 401 anonymous ──

    @Test
    @DisplayName("GET /auth/me — anonymous request IS 401 (catch-all guard)")
    void authMe_Anonymous_ShouldBe401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /tenants — anonymous request IS 401 (catch-all guard)")
    void tenants_Anonymous_ShouldBe401() throws Exception {
        // /api/v1/** falls through anyRequest().authenticated().
        // Regression would let unauthenticated callers list tenants.
        mockMvc.perform(get("/api/v1/tenants"))
                .andExpect(status().isUnauthorized());
    }
}
