package com.fivucsas.identity.multitenancy;

import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.security.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Cross-tenant isolation of the user-scoped enrollment endpoints through the FULL
 * HTTP stack: servlet filters in their real order, the Spring Security chain with
 * a real JWT, method security, controllers and PostgreSQL.
 *
 * <p>Reproduces the AX-5 findings against identity-core-api 2a0d087: a TENANT_ADMIN
 * of tenant A
 * <ol>
 *   <li>read {@code GET /users/{id}/enrollments} of a tenant-B user, with or without
 *       a forged {@code X-Tenant-ID: <tenant B>};</li>
 *   <li>read {@code GET /users/{id}/enrollments/health} of that user with the forged
 *       header;</li>
 *   <li>wrote {@code POST /users/{id}/enrollments} and
 *       {@code PUT /users/{id}/enrollments/FACE/complete} for that user with the
 *       forged header.</li>
 * </ol>
 * Two causes: the {@code hasPermission(#userId, 'User', ...)} evaluator ignored the
 * target id, and {@code TenantContextFilter} ran after the Spring Security chain, so
 * the header overwrote the tenant that {@code TenantBindFromAuthFilter} had bound
 * from the token. The tenant-context probe below pins the second cause on its own.</p>
 *
 * <p>Gated on {@code RUN_INTEGRATION=true} like the other Testcontainers ITs.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Cross-tenant isolation: user-scoped enrollment endpoints over HTTP")
class CrossTenantEnrollmentHttpIT {

    static final String PROBE_PATH = "/api/v1/test-probe/tenant-context";

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_xtenant_http_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    /**
     * Echoes the tenant bound to the request once every other filter has run. A servlet
     * filter registered last (not a controller, so no stereotype is component-scanned
     * into other test contexts).
     */
    @TestConfiguration
    static class ProbeConfig {
        @Bean
        FilterRegistrationBean<OncePerRequestFilter> tenantContextProbe() {
            OncePerRequestFilter probe = new OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                                FilterChain chain) throws IOException {
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write("{\"tenantId\":\"" + TenantContext.getCurrentTenant() + "\"}");
                }
            };
            FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(probe);
            registration.addUrlPatterns(PROBE_PATH);
            registration.setOrder(Ordered.LOWEST_PRECEDENCE);
            return registration;
        }
    }

    @Autowired private MockMvc mvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private JwtService jwtService;

    private UUID systemTenant;
    private UUID tenantA;
    private UUID tenantB;
    private UUID memberA;
    private UUID victimB;
    private String adminAToken;
    private String memberAToken;
    private String rootToken;
    private UUID globalRole;

    @BeforeEach
    void setUp() {
        systemTenant = seedTenant("xth-system");
        tenantA = seedTenant("xth-tenant-a");
        tenantB = seedTenant("xth-tenant-b");

        String rootEmail = "root@" + systemTenant + ".test";
        String adminAEmail = "admina@" + tenantA + ".test";
        seedUser(systemTenant, rootEmail, "ROOT");
        seedUser(tenantA, adminAEmail, "TENANT_ADMIN");
        String memberAEmail = "member@" + tenantA + ".test";
        memberA = seedUser(tenantA, memberAEmail, "TENANT_MEMBER");
        victimB = seedUser(tenantB, "victim@" + tenantB + ".test", "TENANT_MEMBER");

        seedEnrollment(tenantA, memberA, "FACE", "PENDING");
        seedEnrollment(tenantB, victimB, "FACE", "PENDING");

        adminAToken = jwtService.generateAccessToken(adminAEmail);
        memberAToken = jwtService.generateAccessToken(memberAEmail);
        rootToken = jwtService.generateAccessToken(rootEmail);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        jdbc.update("DELETE FROM user_enrollments WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        if (globalRole != null) {
            jdbc.update("DELETE FROM user_roles WHERE role_id = ?", globalRole);
            jdbc.update("DELETE FROM roles WHERE id = ?", globalRole);
            globalRole = null;
        }
        // The V53 trigger forbids hard DELETE of users and tenants; seeds are unique per run.
        jdbc.update("UPDATE users SET deleted_at = NOW() WHERE tenant_id IN (?, ?, ?) AND deleted_at IS NULL",
                systemTenant, tenantA, tenantB);
        jdbc.update("UPDATE tenants SET deleted_at = NOW() WHERE id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
    }

    private MockHttpServletRequestBuilder asAdminA(MockHttpServletRequestBuilder request) {
        return request.header("Authorization", "Bearer " + adminAToken);
    }

    private MockHttpServletRequestBuilder asAdminAForging(MockHttpServletRequestBuilder request, UUID tenant) {
        return asAdminA(request).header("X-Tenant-ID", tenant.toString());
    }

    @Nested
    @DisplayName("Tenant bound to the request")
    class TenantBinding {

        @Test
        void tenantContext_WhenNonRootForgesHeader_ShouldStayOnTheTokenTenant() throws Exception {
            mvc.perform(asAdminAForging(get(PROBE_PATH), tenantB))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value(tenantA.toString()));
        }

        @Test
        void tenantContext_WhenNonRootSendsNoHeader_ShouldUseTheTokenTenant() throws Exception {
            mvc.perform(asAdminA(get(PROBE_PATH)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value(tenantA.toString()));
        }

        @Test
        void tenantContext_WhenRootSwitchesTenant_ShouldUseTheHeaderTenant() throws Exception {
            mvc.perform(get(PROBE_PATH)
                            .header("Authorization", "Bearer " + rootToken)
                            .header("X-Tenant-ID", tenantB.toString()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tenantId").value(tenantB.toString()));
        }
    }

    @Nested
    @DisplayName("Tenant-A admin against a tenant-B user")
    class CrossTenantAccess {

        @Test
        void getUserEnrollments_WhenAdminOfAnotherTenant_ShouldReturn403() throws Exception {
            mvc.perform(asAdminA(get("/api/v1/users/{id}/enrollments", victimB)))
                    .andExpect(status().isForbidden());
        }

        @Test
        void getUserEnrollments_WhenAdminOfAnotherTenantForgesHeader_ShouldReturn403() throws Exception {
            mvc.perform(asAdminAForging(get("/api/v1/users/{id}/enrollments", victimB), tenantB))
                    .andExpect(status().isForbidden());
        }

        @Test
        void getEnrollmentHealth_WhenAdminOfAnotherTenantForgesHeader_ShouldReturn403() throws Exception {
            mvc.perform(asAdminAForging(get("/api/v1/users/{id}/enrollments/health", victimB), tenantB))
                    .andExpect(status().isForbidden());
        }

        @Test
        void startEnrollment_WhenAdminOfAnotherTenantForgesHeader_ShouldReturn403AndWriteNothing() throws Exception {
            List<Map<String, Object>> before = enrollmentsOf(victimB);

            mvc.perform(asAdminAForging(post("/api/v1/users/{id}/enrollments", victimB)
                            .param("tenantId", tenantB.toString())
                            .param("methodType", "VOICE"), tenantB))
                    .andExpect(status().isForbidden());

            assertThat(enrollmentsOf(victimB)).isEqualTo(before);
        }

        @Test
        void completeEnrollment_WhenAdminOfAnotherTenantForgesHeader_ShouldReturn403AndWriteNothing() throws Exception {
            List<Map<String, Object>> before = enrollmentsOf(victimB);

            mvc.perform(asAdminAForging(put("/api/v1/users/{id}/enrollments/FACE/complete", victimB), tenantB))
                    .andExpect(status().isForbidden());

            assertThat(enrollmentsOf(victimB)).isEqualTo(before);
        }

        @Test
        void listDevices_WhenAdminOfAnotherTenantSelectsUserByQueryParam_ShouldReturn403() throws Exception {
            mvc.perform(asAdminAForging(get("/api/v1/devices").param("userId", victimB.toString()), tenantB))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("Positive controls")
    class SameTenantAccess {

        @Test
        void getUserEnrollments_WhenAdminOfSameTenant_ShouldReturn200() throws Exception {
            mvc.perform(asAdminA(get("/api/v1/users/{id}/enrollments", memberA)))
                    .andExpect(status().isOk());
        }

        @Test
        void getUserEnrollments_WhenRootSwitchedToTheTargetTenant_ShouldReturn200() throws Exception {
            mvc.perform(get("/api/v1/users/{id}/enrollments", victimB)
                            .header("Authorization", "Bearer " + rootToken)
                            .header("X-Tenant-ID", tenantB.toString()))
                    .andExpect(status().isOk());
        }

        @Test
        void listDevices_WhenAdminOfSameTenantSelectsUserByQueryParam_ShouldReturn200() throws Exception {
            mvc.perform(asAdminA(get("/api/v1/devices").param("userId", memberA.toString())))
                    .andExpect(status().isOk());
        }

        @Test
        void getUserRoles_WhenAdminOfSameTenant_ShouldReturn200() throws Exception {
            mvc.perform(asAdminA(get("/api/v1/users/{id}/roles", memberA)))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Other user-id endpoints share the same guard")
    class SharedUserGuard {

        @Test
        void getUserRoles_WhenAdminOfAnotherTenantForgesHeader_ShouldReturn403() throws Exception {
            mvc.perform(asAdminAForging(get("/api/v1/users/{id}/roles", victimB), tenantB))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("POST /users/{id}/enrollments: the row's tenant is the user's own tenant")
    class StartEnrollmentTenant {

        @Test
        void startEnrollment_WhenSelfPassesForeignTenantId_ShouldReturn403AndWriteNothing() throws Exception {
            List<Map<String, Object>> before = enrollmentsOf(memberA);

            mvc.perform(post("/api/v1/users/{id}/enrollments", memberA)
                            .header("Authorization", "Bearer " + memberAToken)
                            .param("tenantId", tenantB.toString())
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isForbidden());

            assertThat(enrollmentsOf(memberA)).isEqualTo(before);
        }

        @Test
        void startEnrollment_WhenAdminOfSameTenantPassesForeignTenantId_ShouldReturn403AndWriteNothing()
                throws Exception {
            List<Map<String, Object>> before = enrollmentsOf(memberA);

            mvc.perform(asAdminA(post("/api/v1/users/{id}/enrollments", memberA)
                            .param("tenantId", tenantB.toString())
                            .param("methodType", "EMAIL_OTP")))
                    .andExpect(status().isForbidden());

            assertThat(enrollmentsOf(memberA)).isEqualTo(before);
        }

        @Test
        void startEnrollment_WhenRootPassesTenantOtherThanTheUsers_ShouldReturn400AndWriteNothing()
                throws Exception {
            List<Map<String, Object>> before = enrollmentsOf(memberA);

            mvc.perform(post("/api/v1/users/{id}/enrollments", memberA)
                            .header("Authorization", "Bearer " + rootToken)
                            .header("X-Tenant-ID", tenantB.toString())
                            .param("tenantId", tenantB.toString())
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isBadRequest());

            assertThat(enrollmentsOf(memberA)).isEqualTo(before);
        }

        @Test
        void startEnrollment_WhenRootSwitchedToAnotherTenantOmitsTenantId_ShouldTagTheUsersTenant()
                throws Exception {
            mvc.perform(post("/api/v1/users/{id}/enrollments", memberA)
                            .header("Authorization", "Bearer " + rootToken)
                            .header("X-Tenant-ID", tenantB.toString())
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isCreated());

            assertThat(tenantOfEnrollment(memberA, "EMAIL_OTP")).isEqualTo(tenantA);
        }

        @Test
        void startEnrollment_WhenSelfPassesOwnTenantId_ShouldReturn201() throws Exception {
            mvc.perform(post("/api/v1/users/{id}/enrollments", memberA)
                            .header("Authorization", "Bearer " + memberAToken)
                            .param("tenantId", tenantA.toString())
                            .param("methodType", "EMAIL_OTP"))
                    .andExpect(status().isCreated());

            assertThat(tenantOfEnrollment(memberA, "EMAIL_OTP")).isEqualTo(tenantA);
        }
    }

    @Nested
    @DisplayName("Guest lifecycle and role-holder endpoints")
    class GuestAndRoleHolders {

        @Test
        void revokeGuest_WhenAdminOfAnotherTenant_ShouldReturn403AndLeaveTheUserActive() throws Exception {
            mvc.perform(asAdminA(post("/api/v1/guests/{id}/revoke", victimB)))
                    .andExpect(status().isForbidden());

            assertThat(isActive(victimB)).isTrue();
        }

        @Test
        void extendGuest_WhenAdminOfAnotherTenant_ShouldReturn403() throws Exception {
            mvc.perform(asAdminA(post("/api/v1/guests/{id}/extend", victimB)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"additionalHours\":24}")))
                    .andExpect(status().isForbidden());
        }

        @Test
        void getRoleUsers_WhenAdminUsesGlobalRoleId_ShouldListOnlyHoldersOfOwnTenant() throws Exception {
            globalRole = UUID.randomUUID();
            jdbc.update("INSERT INTO roles (id, tenant_id, name, description, is_active, created_at, updated_at) "
                    + "VALUES (?, NULL, ?, 'xth global role', true, NOW(), NOW())",
                    globalRole, "XTH_GLOBAL_" + globalRole.toString().substring(0, 8));
            jdbc.update("INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, NOW())",
                    memberA, globalRole);
            jdbc.update("INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, NOW())",
                    victimB, globalRole);

            mvc.perform(asAdminA(get("/api/v1/users/{id}/roles/all/{roleId}", memberA, globalRole)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.length()").value(1))
                    .andExpect(jsonPath("$[0].userId").value(memberA.toString()));
        }
    }

    private UUID tenantOfEnrollment(UUID userId, String methodType) {
        return jdbc.queryForObject(
                "SELECT tenant_id FROM user_enrollments WHERE user_id = ? AND auth_method_type = ?",
                UUID.class, userId, methodType);
    }

    private boolean isActive(UUID userId) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT is_active FROM users WHERE id = ?", Boolean.class, userId));
    }

    private List<Map<String, Object>> enrollmentsOf(UUID userId) {
        return jdbc.queryForList(
                "SELECT id, tenant_id, auth_method_type, status, updated_at FROM user_enrollments "
                        + "WHERE user_id = ? ORDER BY auth_method_type", userId);
    }

    private UUID seedTenant(String slug) {
        UUID id = UUID.randomUUID();
        String unique = slug + "-" + id.toString().substring(0, 8);
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, contact_email, status, max_users, " +
                "biometric_enabled, session_timeout_minutes, refresh_token_validity_days, " +
                "is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, 'ACTIVE', 100, true, 30, 7, true, NOW(), NOW())",
                id, "XTH " + unique, unique, unique + "@example.com");
        return id;
    }

    private UUID seedUser(UUID tenantId, String email, String userType) {
        UUID id = UUID.randomUUID();
        UUID identityId = UUID.randomUUID();
        jdbc.update("INSERT INTO identities (id, display_name, status, created_at, updated_at) "
                + "VALUES (?, 'XTH Test', 'ACTIVE', NOW(), NOW())", identityId);
        jdbc.update(
                "INSERT INTO users (id, tenant_id, identity_id, email, password_hash, first_name, last_name, " +
                "user_type, status, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "'XTH', 'Test', ?, 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, identityId, email, userType);
        return id;
    }

    private void seedEnrollment(UUID tenantId, UUID userId, String methodType, String status) {
        jdbc.update(
                "INSERT INTO user_enrollments (id, user_id, tenant_id, auth_method_type, status, " +
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, NOW(), NOW())",
                UUID.randomUUID(), userId, tenantId, methodType, status);
    }
}
