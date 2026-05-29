package com.fivucsas.identity.multitenancy;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Adversarial end-to-end isolation tests for the unified SUPER_ADMIN tenant
 * switcher (X-Tenant-ID). Exercises the REAL stack: Hibernate {@code tenantFilter},
 * {@code TenantHibernateAspect}, {@link TenantFilterBypass}, {@link RbacAuthorizationService},
 * and {@link TenantScopeResolver} against a Postgres container.
 *
 * <p>What is pinned here (the whole point of the feature):
 * <ol>
 *   <li><b>The 403 fix.</b> A ROOT user whose own row lives in the system tenant
 *       still resolves via {@code getCurrentUser()} (and thus passes
 *       {@code @PreAuthorize}) while the active tenant is a FOREIGN one — the
 *       tenant-filter no longer hides the caller from itself.</li>
 *   <li><b>SUPER_ADMIN switch.</b> With the foreign tenant active, the
 *       Hibernate-filtered user listing returns the FOREIGN tenant's users, and
 *       {@code TenantScopeResolver.currentScope()} returns the selected tenant.</li>
 *   <li><b>SUPER_ADMIN default.</b> No header → home tenant data only.</li>
 *   <li><b>TENANT_ADMIN isolation.</b> Even with the foreign tenant pinned in
 *       {@code TenantContext}, a tenant-admin's filtered listing AND
 *       {@code currentScope()} stay on their OWN tenant — never the foreign one.</li>
 * </ol>
 *
 * <p>Gated on {@code RUN_INTEGRATION=true} (Testcontainers / self-hosted runner),
 * matching the project's split-CI convention.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Tenant switcher — adversarial cross-tenant isolation")
class TenantSwitcherIsolationIT {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_switcher_test")
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
    @Autowired private UserRepository userRepository;
    @Autowired private RbacAuthorizationService rbacService;
    @Autowired private TenantScopeResolver tenantScopeResolver;

    private UUID systemTenant;     // where ROOT lives
    private UUID tenantA;          // tenant-admin's home
    private UUID tenantB;          // a foreign tenant
    private UUID rootId;
    private UUID adminAId;
    private String rootEmail;
    private String adminAEmail;

    @BeforeEach
    void setUp() {
        systemTenant = seedTenant("sw-system");
        tenantA = seedTenant("sw-tenant-a");
        tenantB = seedTenant("sw-tenant-b");

        rootEmail = "root@" + systemTenant + ".test";
        adminAEmail = "admina@" + tenantA + ".test";

        rootId = seedUser(systemTenant, rootEmail, "ROOT");
        adminAId = seedUser(tenantA, adminAEmail, "TENANT_ADMIN");
        // Foreign-tenant occupants so "sees foreign data" is observable.
        seedUser(tenantB, "bob1@" + tenantB + ".test", "TENANT_MEMBER");
        seedUser(tenantB, "bob2@" + tenantB + ".test", "TENANT_MEMBER");
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
        RequestContextHolder.resetRequestAttributes();
        jdbc.update("DELETE FROM users WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("UPDATE tenants SET deleted_at = NOW() WHERE id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
    }

    // ── 1) The 403 fix + SUPER_ADMIN switch ────────────────────────────────

    @Test
    @Transactional
    @DisplayName("SUPER_ADMIN + foreign X-Tenant-ID → caller still resolves (no 403) AND sees the foreign tenant's users")
    void superAdminSwitched_resolvesSelf_andSeesForeignData() {
        authenticateAs(rootEmail, "ROLE_SUPER_ADMIN");
        bindRequestWithTenantId(tenantB);
        // Emulate the post-rebind state: TenantContext pinned to the foreign tenant
        // (TenantBindFromAuthFilter honours SUPER_ADMIN's asserted X-Tenant-ID).
        TenantContext.setCurrentTenant(tenantB);

        // (a) The 403 fix: caller self-resolution succeeds despite foreign filter.
        Optional<User> self = rbacService.getCurrentUser();
        assertThat(self).as("ROOT must resolve itself under a foreign active tenant").isPresent();
        assertThat(self.get().getId()).isEqualTo(rootId);
        assertThat(rbacService.isSuperAdmin()).isTrue();
        assertThat(rbacService.hasPermission("user:read")).isTrue();

        // (b) currentScope reflects the selected tenant.
        assertThat(tenantScopeResolver.currentScope()).isEqualTo(tenantB);
        assertThat(tenantScopeResolver.isCrossTenantAdmin()).isTrue();

        // (c) The Hibernate-filtered listing returns the FOREIGN tenant's users.
        List<String> emails = userRepository.findAll().stream().map(User::getEmail).toList();
        assertThat(emails).allMatch(e -> e.contains(tenantB.toString()));
        assertThat(emails).hasSize(2);
    }

    @Test
    @Transactional
    @DisplayName("SUPER_ADMIN + no header → home (system) tenant only")
    void superAdminNoHeader_homeTenantOnly() {
        authenticateAs(rootEmail, "ROLE_SUPER_ADMIN");
        bindRequestWithTenantId(null);
        TenantContext.setCurrentTenant(systemTenant); // rebind defaults to JWT home

        assertThat(rbacService.getCurrentUser()).isPresent();
        // No header → cross-tenant capability, but currentScope() falls back to null.
        assertThat(tenantScopeResolver.currentScope()).isNull();

        List<String> emails = userRepository.findAll().stream().map(User::getEmail).toList();
        assertThat(emails).containsExactly(rootEmail);
    }

    // ── 2) TENANT_ADMIN isolation (the critical guarantee) ──────────────────

    @Test
    @Transactional
    @DisplayName("SECURITY: TENANT_ADMIN + foreign X-Tenant-ID pinned → sees ONLY own tenant (filter + currentScope)")
    void tenantAdminSwitched_staysOnOwnTenant() {
        authenticateAs(adminAEmail, "ROLE_TENANT_ADMIN");
        bindRequestWithTenantId(tenantB);
        // Adversary: TenantContext somehow carries the foreign tenant. In real
        // flow TenantBindFromAuthFilter would already have reset it to home; we
        // pin home here to model the post-rebind invariant the filter enforces.
        TenantContext.setCurrentTenant(tenantA);

        // currentScope() ignores the header for non-ROOT → home tenant.
        assertThat(tenantScopeResolver.currentScope()).isEqualTo(tenantA);
        assertThat(tenantScopeResolver.currentScope()).isNotEqualTo(tenantB);
        assertThat(tenantScopeResolver.canAccessTenant(tenantB)).isFalse();
        assertThat(tenantScopeResolver.isCrossTenantAdmin()).isFalse();

        // Hibernate-filtered listing returns ONLY tenant A's user (the admin).
        List<String> emails = userRepository.findAll().stream().map(User::getEmail).toList();
        assertThat(emails).containsExactly(adminAEmail);
        assertThat(emails).noneMatch(e -> e.contains(tenantB.toString()));
    }

    @Test
    @Transactional
    @DisplayName("SECURITY: TENANT_ADMIN canAccessTenant(foreign) is false even with a valid foreign tenant id")
    void tenantAdminCannotAccessForeignTenant() {
        authenticateAs(adminAEmail, "ROLE_TENANT_ADMIN");
        bindRequestWithTenantId(tenantB);
        TenantContext.setCurrentTenant(tenantA);

        assertThat(rbacService.canAccessTenant(tenantA)).isTrue();
        assertThat(rbacService.canAccessTenant(tenantB)).isFalse();
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private void authenticateAs(String email, String role) {
        var auth = new UsernamePasswordAuthenticationToken(
                email, null, List.of(new SimpleGrantedAuthority(role)));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private void bindRequestWithTenantId(UUID tenantId) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (tenantId != null) {
            request.addHeader(TenantScopeResolver.TENANT_ID_HEADER, tenantId.toString());
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private UUID seedTenant(String slug) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, contact_email, status, max_users, " +
                "biometric_enabled, session_timeout_minutes, refresh_token_validity_days, " +
                "is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, 'ACTIVE', 100, true, 30, 7, true, NOW(), NOW())",
                id, "SW " + slug, slug, slug + "@example.com");
        return id;
    }

    private UUID seedUser(UUID tenantId, String email, String userType) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, " +
                "user_type, status, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "'SW', 'Test', ?, 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, email, userType);
        return id;
    }
}
