package com.fivucsas.identity.multitenancy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fivucsas.identity.infrastructure.multitenancy.TenantBindFromAuthFilter;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.security.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * F4 — {@link TenantBindFromAuthFilter} regression test (PR #54 contract).
 *
 * <p>Asserts: header asserts tenantB while JWT principal lives in tenantA →
 * filter overwrites context to tenantA, emits the AUDIT line, and a
 * tenant-scoped query returns only tenantA's row. SUPER_ADMIN may legitimately
 * cross tenants. No header → bind to JWT tenant.</p>
 *
 * <p>NB: in production the JWT filter populates the principal with Spring's
 * stock {@code User}, not {@code CustomUserDetails} — the rebind filter's
 * {@code instanceof} check therefore short-circuits in real flow (separate
 * audit-tracked bug). This test covers the contract as specified by javadoc;
 * a follow-up wires {@code CustomUserDetails} through the JWT filter.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("F4 — TenantBindFromAuthFilter cross-tenant rebind regression")
class TenantRlsRegressionTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_f4_test")
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

    private final TenantBindFromAuthFilter filter = new TenantBindFromAuthFilter();

    private UUID tenantA;
    private UUID tenantB;
    private UUID aliceId;
    private UUID bobId;

    private ListAppender<ILoggingEvent> logCapture;

    @BeforeEach
    void setUp() {
        tenantA = seedTenant("f4-tenant-a");
        tenantB = seedTenant("f4-tenant-b");
        aliceId = seedUser(tenantA, "alice@" + tenantA + ".test");
        bobId   = seedUser(tenantB, "bob@" + tenantB + ".test");

        logCapture = new ListAppender<>();
        logCapture.start();
        Logger filterLogger = (Logger) LoggerFactory.getLogger(TenantBindFromAuthFilter.class);
        filterLogger.setLevel(Level.DEBUG);
        filterLogger.addAppender(logCapture);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
        Logger filterLogger = (Logger) LoggerFactory.getLogger(TenantBindFromAuthFilter.class);
        filterLogger.detachAppender(logCapture);
        // Best-effort cleanup so the container can be reused across tests.
        jdbc.update("DELETE FROM users WHERE id IN (?, ?)", aliceId, bobId);
        jdbc.update("UPDATE tenants SET deleted_at = NOW() WHERE id IN (?, ?)", tenantA, tenantB);
    }

    @Test
    @DisplayName("non-SUPER_ADMIN: X-Tenant-ID=tenantB rebinds to JWT tenantA, audit logged")
    void crossTenantHeader_nonSuperAdmin_isRebound() throws Exception {
        // Simulate the JWT filter having authenticated alice@tenantA.
        authenticateAs(aliceId, "alice@example.com", tenantA, "ROLE_USER");
        // Simulate TenantContextFilter having honored the asserted X-Tenant-ID header (tenantB).
        TenantContext.setCurrentTenant(tenantB);

        invokeFilter();

        // Filter must have overwritten the asserted tenantId.
        assertThat(TenantContext.getCurrentTenant()).isEqualTo(tenantA);

        // Tenant-scoped query honours TenantContext → only alice's row visible.
        List<UUID> visibleUserIds = jdbc.queryForList(
                "SELECT id FROM users WHERE tenant_id = ?", UUID.class,
                TenantContext.getCurrentTenant());
        assertThat(visibleUserIds).containsExactly(aliceId);

        // AUDIT line emitted.
        assertThat(logCapture.list)
                .anyMatch(e -> e.getFormattedMessage()
                        .contains("AUDIT: tenant-rebind rejected cross-tenant assertion"));
    }

    @Test
    @DisplayName("SUPER_ADMIN: X-Tenant-ID=tenantB is honored, no rebind")
    void crossTenantHeader_superAdmin_isHonored() throws Exception {
        authenticateAs(aliceId, "alice@example.com", tenantA, "ROLE_SUPER_ADMIN");
        TenantContext.setCurrentTenant(tenantB);

        invokeFilter();

        assertThat(TenantContext.getCurrentTenant()).isEqualTo(tenantB);

        // Tenant-scoped query reflects the (intentionally) overridden context — bob's row.
        List<UUID> visibleUserIds = jdbc.queryForList(
                "SELECT id FROM users WHERE tenant_id = ?", UUID.class,
                TenantContext.getCurrentTenant());
        assertThat(visibleUserIds).containsExactly(bobId);

        assertThat(logCapture.list)
                .anyMatch(e -> e.getFormattedMessage()
                        .contains("SUPER_ADMIN tenant override accepted"));
    }

    @Test
    @DisplayName("no header asserted: filter binds context to JWT-derived tenantId")
    void noHeaderAsserted_bindsToJwtTenant() throws Exception {
        authenticateAs(aliceId, "alice@example.com", tenantA, "ROLE_USER");
        TenantContext.clear();   // emulate request without X-Tenant-ID

        invokeFilter();

        assertThat(TenantContext.getCurrentTenant()).isEqualTo(tenantA);
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private void invokeFilter() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(req, res, chain);
        Mockito.verify(chain).doFilter(req, res);
    }

    private void authenticateAs(UUID userId, String email, UUID tenantId, String role) {
        CustomUserDetails details = new CustomUserDetails(
                userId, email, "{noop}irrelevant", tenantId, true,
                List.of(new SimpleGrantedAuthority(role)));
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                details, null, details.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private UUID seedTenant(String slug) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, contact_email, status, max_users, " +
                "biometric_enabled, session_timeout_minutes, refresh_token_validity_days, " +
                "is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, 'ACTIVE', 100, true, 30, 7, true, NOW(), NOW())",
                id, "F4 " + slug, slug, slug + "@example.com");
        return id;
    }

    private UUID seedUser(UUID tenantId, String email) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, " +
                "status, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "'F4', 'Test', 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, email);
        return id;
    }
}
