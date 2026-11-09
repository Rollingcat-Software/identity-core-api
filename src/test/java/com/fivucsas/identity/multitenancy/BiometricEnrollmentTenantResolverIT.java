package com.fivucsas.identity.multitenancy;

import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.security.BiometricEnrollmentTenantResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Real-stack test of {@link BiometricEnrollmentTenantResolver} (issue #284):
 * Hibernate {@code tenantFilter}, {@code TenantHibernateAspect},
 * {@code TenantFilterBypass} and the RBAC lookups against Postgres.
 *
 * <p>Deliberately NOT {@code @Transactional} at test level and run without a web
 * request (so no open-in-view EntityManager): the resolver must open its own
 * transaction, which {@code TenantFilterBypass} requires. Each case pins the
 * active tenant in {@link TenantContext} the way {@code TenantBindFromAuthFilter}
 * does for a request, so the filter is live while the subject is looked up.</p>
 *
 * <p>Gated on {@code RUN_INTEGRATION=true}, like the other tenant-isolation ITs.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Biometric enroll tenant resolver under the live tenant filter")
class BiometricEnrollmentTenantResolverIT {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_enroll_tenant_test")
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
    @Autowired private BiometricEnrollmentTenantResolver resolver;

    private UUID systemTenant;
    private UUID tenantA;
    private UUID tenantB;
    private UUID rootId;
    private UUID memberAId;
    private UUID memberBId;
    private String rootEmail;
    private String adminAEmail;
    private String memberAEmail;

    @BeforeEach
    void setUp() {
        systemTenant = seedTenant("et-system");
        tenantA = seedTenant("et-tenant-a");
        tenantB = seedTenant("et-tenant-b");

        rootEmail = "root@" + systemTenant + ".test";
        adminAEmail = "admina@" + tenantA + ".test";
        memberAEmail = "membera@" + tenantA + ".test";

        rootId = seedUser(systemTenant, rootEmail, "ROOT");
        seedUser(tenantA, adminAEmail, "TENANT_ADMIN");
        memberAId = seedUser(tenantA, memberAEmail, "TENANT_MEMBER");
        memberBId = seedUser(tenantB, "memberb@" + tenantB + ".test", "TENANT_MEMBER");
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
        // V53 forbids hard DELETE on users; seeds are unique per run.
        jdbc.update("UPDATE users SET deleted_at = NOW() WHERE tenant_id IN (?, ?, ?) AND deleted_at IS NULL",
                systemTenant, tenantA, tenantB);
        jdbc.update("UPDATE tenants SET deleted_at = NOW() WHERE id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
    }

    @Test
    void resolve_WhenRootBrowsingTenantAEnrollsUserOfTenantB_ShouldReturnTenantB() {
        actAs(rootEmail, "ROLE_ROOT", tenantA);

        assertThat(resolver.resolve(memberBId, null)).isEqualTo(tenantB.toString());
    }

    @Test
    void resolve_WhenRootBrowsingTenantAEnrollsItself_ShouldReturnItsOwnTenant() {
        actAs(rootEmail, "ROLE_ROOT", tenantA);

        assertThat(resolver.resolve(rootId, null)).isEqualTo(systemTenant.toString());
    }

    @Test
    void resolve_WhenTenantAdminEnrollsUserOfItsTenant_ShouldReturnThatTenant() {
        actAs(adminAEmail, "ROLE_TENANT_ADMIN", tenantA);

        assertThat(resolver.resolve(memberAId, tenantB.toString())).isEqualTo(tenantA.toString());
    }

    @Test
    void resolve_WhenTenantAdminEnrollsUserOfAnotherTenant_ShouldDeny() {
        actAs(adminAEmail, "ROLE_TENANT_ADMIN", tenantA);

        assertThatThrownBy(() -> resolver.resolve(memberBId, null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void resolve_WhenTenantAdminNamesUnknownUser_ShouldDenyLikeAForeignUser() {
        actAs(adminAEmail, "ROLE_TENANT_ADMIN", tenantA);

        assertThatThrownBy(() -> resolver.resolve(UUID.randomUUID(), null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void resolve_WhenMemberEnrollsItself_ShouldReturnItsTenant() {
        actAs(memberAEmail, "ROLE_TENANT_MEMBER", tenantA);

        assertThat(resolver.resolve(memberAId, null)).isEqualTo(tenantA.toString());
    }

    @Test
    void assertMayEnroll_WhenMemberEnrollsUserOfAnotherTenant_ShouldDeny() {
        actAs(memberAEmail, "ROLE_TENANT_MEMBER", tenantA);

        assertThatThrownBy(() -> resolver.assertMayEnroll(memberBId))
                .isInstanceOf(AccessDeniedException.class);
    }

    // helpers

    private void actAs(String email, String role, UUID activeTenant) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                email, null, List.of(new SimpleGrantedAuthority(role))));
        TenantContext.setCurrentTenant(activeTenant);
    }

    private UUID seedTenant(String slug) {
        UUID id = UUID.randomUUID();
        String unique = slug + "-" + id.toString().substring(0, 8);
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, contact_email, status, max_users, "
                        + "biometric_enabled, session_timeout_minutes, refresh_token_validity_days, "
                        + "is_active, created_at, updated_at) "
                        + "VALUES (?, ?, ?, ?, 'ACTIVE', 100, true, 30, 7, true, NOW(), NOW())",
                id, "ET " + unique, unique, unique + "@example.com");
        return id;
    }

    private UUID seedUser(UUID tenantId, String email, String userType) {
        UUID id = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        jdbc.update("INSERT INTO identities (id, display_name, status, created_at, updated_at) "
                + "VALUES (?, 'ET Test', 'ACTIVE', NOW(), NOW())", identityId);
        jdbc.update(
                "INSERT INTO users (id, tenant_id, identity_id, email, password_hash, first_name, last_name, "
                        + "user_type, status, is_active, created_at, updated_at) "
                        + "VALUES (?, ?, ?, ?, '$2a$10$dummyhashfortesting.................................', "
                        + "'ET', 'Test', ?, 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, identityId, email, userType);
        return id;
    }
}
