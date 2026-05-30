package com.fivucsas.identity.multitenancy;

import com.fivucsas.identity.application.dto.response.AuthFlowResponse;
import com.fivucsas.identity.application.dto.response.DeviceResponse;
import com.fivucsas.identity.application.dto.response.VerificationSessionResponse;
import com.fivucsas.identity.controller.AuditLogController;
import com.fivucsas.identity.controller.AuthSessionController;
import com.fivucsas.identity.controller.DeviceController;
import com.fivucsas.identity.controller.EnrollmentController;
import com.fivucsas.identity.controller.VerificationController;
import com.fivucsas.identity.dto.AuditLogDto;
import com.fivucsas.identity.dto.EnrollmentDto;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import com.fivucsas.identity.security.TenantScopeResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Adversarial cross-tenant ISOLATION integration tests for the tenant-scoped
 * admin <b>list</b> endpoints that do NOT yet carry a Hibernate {@code @Filter}
 * and rely SOLELY on controller-level {@link TenantScopeResolver#currentScope()}
 * scoping: audit-logs, auth-sessions, devices, enrollments, verification
 * sessions and verification flows.
 *
 * <p><b>Why this exists (P0-1 STEP 1 — TEST-FIRST).</b> A later task will add the
 * Hibernate {@code tenantFilter} to {@code AuditLog}, {@code AuthSession},
 * {@code MfaSession}, {@code UserEnrollment}, {@code VerificationSession},
 * {@code OAuth2Client}, {@code UserDevice} and {@code AuthFlow} (today only
 * {@code User} + {@code Role} carry it). These tests capture the CURRENT
 * cross-tenant behaviour BEFORE that change so the @Filter rollout can be proven
 * not to regress isolation — and so we can document which entities are already
 * safe via controller-scoping vs which truly NEED the filter.</p>
 *
 * <p><b>What each endpoint is checked against</b> (the four scenarios from the
 * hardening roadmap):
 * <ol>
 *   <li>TENANT_ADMIN of A, no header → sees ONLY A's rows.</li>
 *   <li>TENANT_ADMIN of A + foreign {@code X-Tenant-ID: B} → STILL sees ONLY A's
 *       rows. <b>The critical isolation guarantee</b>: the header MUST be ignored
 *       for a non-ROOT. Assertions here are written to the SECURE
 *       expectation; a failure is a genuine LEAK finding, not a test bug.</li>
 *   <li>ROOT + {@code X-Tenant-ID: B} → sees B's rows (switch works).</li>
 *   <li>ROOT + no header → cross-tenant / platform-wide per current code.</li>
 * </ol></p>
 *
 * <p>This drives the REAL controllers as Spring beans (so the same
 * {@code TenantScopeResolver.currentScope()} logic the HTTP layer uses runs),
 * with the {@link SecurityContextHolder} and the request-scoped
 * {@code X-Tenant-ID} header bound exactly as {@code TenantSwitcherIsolationIT}
 * does. Method-level {@code @PreAuthorize} is not re-evaluated on direct bean
 * calls — the authorization gate is already covered by
 * {@code TenantSwitcherIsolationIT}; here we isolate DATA scoping.</p>
 *
 * <p>Gated on {@code RUN_INTEGRATION=true} (Testcontainers / self-hosted runner),
 * matching the project's split-CI convention and {@code TenantSwitcherIsolationIT}.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Cross-tenant isolation — controller-scoped admin list endpoints")
class CrossTenantIsolationIT {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_isolation_test")
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
    @Autowired private AuditLogController auditLogController;
    @Autowired private AuthSessionController authSessionController;
    @Autowired private DeviceController deviceController;
    @Autowired private EnrollmentController enrollmentController;
    @Autowired private VerificationController verificationController;

    private UUID systemTenant;   // where ROOT lives
    private UUID tenantA;        // tenant-admin's home
    private UUID tenantB;        // the foreign tenant

    private UUID userA;          // a user in tenant A
    private UUID userB;          // a user in tenant B
    private String rootEmail;
    private String adminAEmail;

    private UUID flowA;          // an AUTHENTICATION flow for tenant A
    private UUID flowB;          // a VERIFICATION flow for tenant B
    private UUID verifFlowA;     // a VERIFICATION flow for tenant A

    @BeforeEach
    void setUp() {
        systemTenant = seedTenant("iso-system");
        tenantA = seedTenant("iso-tenant-a");
        tenantB = seedTenant("iso-tenant-b");

        rootEmail = "root@" + systemTenant + ".test";
        adminAEmail = "admina@" + tenantA + ".test";

        seedUser(systemTenant, rootEmail, "ROOT");
        userA = seedUser(tenantA, adminAEmail, "TENANT_ADMIN");
        userB = seedUser(tenantB, "bob@" + tenantB + ".test", "TENANT_MEMBER");

        // Auth flows (FK target for sessions / verification sessions).
        flowA = seedAuthFlow(tenantA, "flow-a-login", "AUTHENTICATION", "APP_LOGIN");
        verifFlowA = seedAuthFlow(tenantA, "flow-a-verify", "VERIFICATION", "ENROLLMENT");
        flowB = seedAuthFlow(tenantB, "flow-b-verify", "VERIFICATION", "ENROLLMENT");

        // One distinguishable row per table, per tenant.
        seedAuditLog(tenantA, userA, "TENANT_A_ACTION");
        seedAuditLog(tenantB, userB, "TENANT_B_ACTION");

        seedAuthSession(tenantA, userA, flowA);
        seedAuthSession(tenantB, userB, flowB);

        seedDevice(tenantA, userA, "device-A");
        seedDevice(tenantB, userB, "device-B");

        seedEnrollment(tenantA, userA, "FACE");
        seedEnrollment(tenantB, userB, "FACE");

        seedVerificationSession(tenantA, userA, verifFlowA);
        seedVerificationSession(tenantB, userB, flowB);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
        RequestContextHolder.resetRequestAttributes();
        jdbc.update("DELETE FROM verification_sessions WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("DELETE FROM user_enrollments WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("DELETE FROM user_devices WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("DELETE FROM auth_sessions WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("DELETE FROM auth_flows WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("DELETE FROM audit_logs WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("DELETE FROM users WHERE tenant_id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
        jdbc.update("UPDATE tenants SET deleted_at = NOW() WHERE id IN (?, ?, ?)", systemTenant, tenantA, tenantB);
    }

    // ════════════════════════════════════════════════════════════════════
    //  GET /api/v1/audit-logs   (AuditLogController#getAuditLogs)
    // ════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GET /api/v1/audit-logs")
    class AuditLogs {

        @Test @Transactional
        @DisplayName("(1) TENANT_ADMIN A, no header → only A's audit logs")
        void tenantAdminNoHeader_onlyOwn() {
            asTenantAdminA(null);
            List<String> tenants = auditLogTenantIds();
            assertThat(tenants).containsOnly(tenantA.toString());
        }

        @Test @Transactional
        @DisplayName("(2) SECURITY: TENANT_ADMIN A + foreign X-Tenant-ID:B → STILL only A's logs (header ignored)")
        void tenantAdminForeignHeader_stillOnlyOwn() {
            asTenantAdminA(tenantB);
            List<String> tenants = auditLogTenantIds();
            assertThat(tenants)
                    .as("TENANT_ADMIN must never see tenant B's audit logs via a forged X-Tenant-ID")
                    .containsOnly(tenantA.toString());
            assertThat(tenants).doesNotContain(tenantB.toString());
        }

        @Test @Transactional
        @DisplayName("(3) ROOT + X-Tenant-ID:B → sees B's logs")
        void superAdminForeignHeader_seesB() {
            asSuperAdmin(tenantB);
            assertThat(auditLogTenantIds()).containsOnly(tenantB.toString());
        }

        @Test @Transactional
        @DisplayName("(4) ROOT + no header → cross-tenant (sees both A and B)")
        void superAdminNoHeader_crossTenant() {
            asSuperAdmin(null);
            assertThat(auditLogTenantIds())
                    .contains(tenantA.toString(), tenantB.toString());
        }

        @SuppressWarnings("unchecked")
        private List<String> auditLogTenantIds() {
            ResponseEntity<Map<String, Object>> resp =
                    auditLogController.getAuditLogs(0, 100, null, null);
            List<AuditLogDto> content = (List<AuditLogDto>) resp.getBody().get("content");
            return content.stream().map(AuditLogDto::getTenantId).toList();
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  GET /api/v1/auth/sessions   (AuthSessionController#listSessions)
    // ════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GET /api/v1/auth/sessions")
    class AuthSessions {

        @Test @Transactional
        @DisplayName("(1) TENANT_ADMIN A, no header → only A's sessions")
        void tenantAdminNoHeader_onlyOwn() {
            asTenantAdminA(null);
            assertThat(sessionTenantIds()).containsOnly(tenantA);
        }

        @Test @Transactional
        @DisplayName("(2) SECURITY: TENANT_ADMIN A + foreign X-Tenant-ID:B → STILL only A's sessions")
        void tenantAdminForeignHeader_stillOnlyOwn() {
            asTenantAdminA(tenantB);
            assertThat(sessionTenantIds())
                    .as("TENANT_ADMIN must never see tenant B's auth sessions via a forged X-Tenant-ID")
                    .containsOnly(tenantA);
            assertThat(sessionTenantIds()).doesNotContain(tenantB);
        }

        @Test @Transactional
        @DisplayName("(3) ROOT + X-Tenant-ID:B → sees B's sessions")
        void superAdminForeignHeader_seesB() {
            asSuperAdmin(tenantB);
            assertThat(sessionTenantIds()).containsOnly(tenantB);
        }

        @Test @Transactional
        @DisplayName("(4) ROOT + no header → platform-wide (sees both A and B)")
        void superAdminNoHeader_crossTenant() {
            asSuperAdmin(null);
            assertThat(sessionTenantIds()).contains(tenantA, tenantB);
        }

        @SuppressWarnings("unchecked")
        private List<UUID> sessionTenantIds() {
            ResponseEntity<Map<String, Object>> resp =
                    authSessionController.listSessions(null, null, null, 0, 100);
            List<com.fivucsas.identity.application.dto.response.AuthSessionListItemResponse> content =
                    (List<com.fivucsas.identity.application.dto.response.AuthSessionListItemResponse>)
                            resp.getBody().get("content");
            return content.stream()
                    .map(com.fivucsas.identity.application.dto.response.AuthSessionListItemResponse::tenantId)
                    .toList();
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  GET /api/v1/devices   (DeviceController#getDevices)
    //  DeviceResponse does not expose tenantId, so we distinguish by name.
    // ════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GET /api/v1/devices")
    class Devices {

        @Test @Transactional
        @DisplayName("(1) TENANT_ADMIN A, no header → only A's devices")
        void tenantAdminNoHeader_onlyOwn() {
            asTenantAdminA(null);
            assertThat(deviceNames()).containsOnly("device-A");
        }

        @Test @Transactional
        @DisplayName("(2) SECURITY: TENANT_ADMIN A + foreign X-Tenant-ID:B → STILL only A's devices")
        void tenantAdminForeignHeader_stillOnlyOwn() {
            asTenantAdminA(tenantB);
            assertThat(deviceNames())
                    .as("TENANT_ADMIN must never see tenant B's devices via a forged X-Tenant-ID")
                    .containsOnly("device-A");
            assertThat(deviceNames()).doesNotContain("device-B");
        }

        @Test @Transactional
        @DisplayName("(3) ROOT + X-Tenant-ID:B → sees B's devices")
        void superAdminForeignHeader_seesB() {
            asSuperAdmin(tenantB);
            assertThat(deviceNames()).containsOnly("device-B");
        }

        @Test @Transactional
        @DisplayName("(4) ROOT + no header → all devices (sees both A and B)")
        void superAdminNoHeader_crossTenant() {
            asSuperAdmin(null);
            assertThat(deviceNames()).contains("device-A", "device-B");
        }

        private List<String> deviceNames() {
            ResponseEntity<List<DeviceResponse>> resp = deviceController.getDevices(null, null);
            return resp.getBody().stream().map(DeviceResponse::deviceName).toList();
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  GET /api/v1/enrollments   (EnrollmentController#getAllEnrollments)
    // ════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GET /api/v1/enrollments")
    class Enrollments {

        @Test @Transactional
        @DisplayName("(1) TENANT_ADMIN A, no header → only A's enrollments")
        void tenantAdminNoHeader_onlyOwn() {
            asTenantAdminA(null);
            assertThat(enrollmentTenantIds()).containsOnly(tenantA.toString());
        }

        @Test @Transactional
        @DisplayName("(2) SECURITY: TENANT_ADMIN A + foreign X-Tenant-ID:B → STILL only A's enrollments")
        void tenantAdminForeignHeader_stillOnlyOwn() {
            asTenantAdminA(tenantB);
            assertThat(enrollmentTenantIds())
                    .as("TENANT_ADMIN must never see tenant B's enrollments via a forged X-Tenant-ID")
                    .containsOnly(tenantA.toString());
            assertThat(enrollmentTenantIds()).doesNotContain(tenantB.toString());
        }

        @Test @Transactional
        @DisplayName("(3) ROOT + X-Tenant-ID:B → sees B's enrollments")
        void superAdminForeignHeader_seesB() {
            asSuperAdmin(tenantB);
            assertThat(enrollmentTenantIds()).containsOnly(tenantB.toString());
        }

        @Test @Transactional
        @DisplayName("(4) ROOT + no header → cross-tenant (sees both A and B)")
        void superAdminNoHeader_crossTenant() {
            asSuperAdmin(null);
            assertThat(enrollmentTenantIds()).contains(tenantA.toString(), tenantB.toString());
        }

        private List<String> enrollmentTenantIds() {
            ResponseEntity<List<EnrollmentDto>> resp = enrollmentController.getAllEnrollments();
            return resp.getBody().stream().map(EnrollmentDto::getTenantId).toList();
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  GET /api/v1/verification/sessions   (VerificationController#listSessions)
    // ════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GET /api/v1/verification/sessions")
    class VerificationSessions {

        @Test @Transactional
        @DisplayName("(1) TENANT_ADMIN A, no header → only A's verification sessions")
        void tenantAdminNoHeader_onlyOwn() {
            asTenantAdminA(null);
            assertThat(verifSessionTenantIds()).containsOnly(tenantA);
        }

        @Test @Transactional
        @DisplayName("(2) SECURITY: TENANT_ADMIN A + foreign X-Tenant-ID:B → STILL only A's verification sessions")
        void tenantAdminForeignHeader_stillOnlyOwn() {
            asTenantAdminA(tenantB);
            assertThat(verifSessionTenantIds())
                    .as("TENANT_ADMIN must never see tenant B's verification sessions via a forged X-Tenant-ID")
                    .containsOnly(tenantA);
            assertThat(verifSessionTenantIds()).doesNotContain(tenantB);
        }

        @Test @Transactional
        @DisplayName("(3) ROOT + X-Tenant-ID:B → sees B's verification sessions")
        void superAdminForeignHeader_seesB() {
            asSuperAdmin(tenantB);
            assertThat(verifSessionTenantIds()).containsOnly(tenantB);
        }

        @Test @Transactional
        @DisplayName("(4) ROOT + no header → platform-wide (sees both A and B)")
        void superAdminNoHeader_crossTenant() {
            asSuperAdmin(null);
            assertThat(verifSessionTenantIds()).contains(tenantA, tenantB);
        }

        private List<UUID> verifSessionTenantIds() {
            ResponseEntity<List<VerificationSessionResponse>> resp =
                    verificationController.listSessions(null);
            return resp.getBody().stream().map(VerificationSessionResponse::tenantId).toList();
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  GET /api/v1/verification/flows   (VerificationController#listFlows)
    // ════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GET /api/v1/verification/flows")
    class VerificationFlows {

        @Test @Transactional
        @DisplayName("(1) TENANT_ADMIN A, no header → only A's verification flows")
        void tenantAdminNoHeader_onlyOwn() {
            asTenantAdminA(null);
            assertThat(flowTenantIds()).containsOnly(tenantA);
        }

        @Test @Transactional
        @DisplayName("(2) SECURITY: TENANT_ADMIN A + foreign X-Tenant-ID:B → STILL only A's verification flows")
        void tenantAdminForeignHeader_stillOnlyOwn() {
            asTenantAdminA(tenantB);
            assertThat(flowTenantIds())
                    .as("TENANT_ADMIN must never see tenant B's verification flows via a forged X-Tenant-ID")
                    .containsOnly(tenantA);
            assertThat(flowTenantIds()).doesNotContain(tenantB);
        }

        @Test @Transactional
        @DisplayName("(3) ROOT + X-Tenant-ID:B → sees B's verification flows")
        void superAdminForeignHeader_seesB() {
            asSuperAdmin(tenantB);
            assertThat(flowTenantIds()).containsOnly(tenantB);
        }

        @Test @Transactional
        @DisplayName("(4) ROOT + no header → platform-wide (sees both A and B verification flows)")
        void superAdminNoHeader_crossTenant() {
            asSuperAdmin(null);
            assertThat(flowTenantIds()).contains(tenantA, tenantB);
        }

        private List<UUID> flowTenantIds() {
            ResponseEntity<List<AuthFlowResponse>> resp = verificationController.listFlows(null);
            return resp.getBody().stream().map(AuthFlowResponse::tenantId).toList();
        }
    }

    // ════════════════════════════════════════════════════════════════════
    //  Context helpers (mirror TenantSwitcherIsolationIT)
    // ════════════════════════════════════════════════════════════════════

    /**
     * Authenticate as the tenant-admin of A and (optionally) forge a foreign
     * X-Tenant-ID header. {@code currentScope()} must IGNORE the header for a
     * non-ROOT, so we model the post-rebind invariant by pinning
     * {@code TenantContext} to A (TenantBindFromAuthFilter would have done so).
     */
    private void asTenantAdminA(UUID foreignHeaderTenant) {
        authenticateAs(adminAEmail, "ROLE_TENANT_ADMIN");
        bindRequestWithTenantId(foreignHeaderTenant);
        TenantContext.setCurrentTenant(tenantA);
    }

    /**
     * Authenticate as the ROOT. With a header present, the switcher
     * pins {@code TenantContext} to that tenant; without one it defaults to the
     * system (home) tenant. {@code currentScope()} honours the header for ROOT.
     */
    private void asSuperAdmin(UUID activeTenant) {
        authenticateAs(rootEmail, "ROLE_ROOT");
        bindRequestWithTenantId(activeTenant);
        TenantContext.setCurrentTenant(activeTenant != null ? activeTenant : systemTenant);
    }

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

    // ════════════════════════════════════════════════════════════════════
    //  Fixture seeding (raw SQL — mirrors TenantSwitcherIsolationIT)
    // ════════════════════════════════════════════════════════════════════

    private UUID seedTenant(String slug) {
        UUID id = UUID.randomUUID();
        // tenants.name + tenants.slug are UNIQUE, and tearDown only SOFT-deletes
        // (the V53 trigger forbids hard-delete), so a fixed name/slug collides on
        // the NEXT @Test's setUp. Suffix both with the row id to stay unique
        // across methods while keeping the human-readable prefix.
        String unique = slug + "-" + id.toString().substring(0, 8);
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, contact_email, status, max_users, " +
                "biometric_enabled, session_timeout_minutes, refresh_token_validity_days, " +
                "is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, 'ACTIVE', 100, true, 30, 7, true, NOW(), NOW())",
                id, "ISO " + unique, unique, unique + "@example.com");
        return id;
    }

    private UUID seedUser(UUID tenantId, String email, String userType) {
        UUID id = UUID.randomUUID();
        // users.identity_id is NOT NULL since V70. Seed an identity explicitly
        // (don't rely on the BEFORE-INSERT trigger) so a later Hibernate UPDATE
        // of this row never trips the constraint.
        UUID identityId = seedIdentity("ISO Test");
        jdbc.update(
                "INSERT INTO users (id, tenant_id, identity_id, email, password_hash, first_name, last_name, " +
                "user_type, status, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, '$2a$10$dummyhashfortesting.................................', " +
                "'ISO', 'Test', ?, 'ACTIVE', true, NOW(), NOW())",
                id, tenantId, identityId, email, userType);
        return id;
    }

    private UUID seedIdentity(String displayName) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO identities (id, display_name, status, created_at, updated_at) "
                + "VALUES (?, ?, 'ACTIVE', NOW(), NOW())", id, displayName);
        return id;
    }

    private UUID seedAuthFlow(UUID tenantId, String name, String flowType, String operationType) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO auth_flows (id, tenant_id, name, description, flow_type, operation_type, " +
                "is_default, is_active, created_at, updated_at) " +
                "VALUES (?, ?, ?, 'iso test flow', ?, ?, false, true, NOW(), NOW())",
                id, tenantId, name, flowType, operationType);
        return id;
    }

    private void seedAuditLog(UUID tenantId, UUID userId, String action) {
        jdbc.update(
                "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource_type, success, created_at) " +
                "VALUES (?, ?, ?, ?, 'TEST', true, NOW())",
                UUID.randomUUID(), tenantId, userId, action);
    }

    private void seedAuthSession(UUID tenantId, UUID userId, UUID flowId) {
        jdbc.update(
                "INSERT INTO auth_sessions (id, user_id, tenant_id, auth_flow_id, operation_type, " +
                "status, current_step_order, started_at, expires_at) " +
                "VALUES (?, ?, ?, ?, 'APP_LOGIN', 'IN_PROGRESS', 1, NOW(), NOW() + INTERVAL '1 hour')",
                UUID.randomUUID(), userId, tenantId, flowId);
    }

    private void seedDevice(UUID tenantId, UUID userId, String name) {
        jdbc.update(
                "INSERT INTO user_devices (id, user_id, tenant_id, device_name, platform, " +
                "device_fingerprint, capabilities, is_trusted, registered_at) " +
                "VALUES (?, ?, ?, ?, 'WEB', ?, '{}', false, NOW())",
                UUID.randomUUID(), userId, tenantId, name, "fp-" + UUID.randomUUID());
    }

    private void seedEnrollment(UUID tenantId, UUID userId, String methodType) {
        jdbc.update(
                "INSERT INTO user_enrollments (id, user_id, tenant_id, auth_method_type, status, " +
                "created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, 'ENROLLED', NOW(), NOW())",
                UUID.randomUUID(), userId, tenantId, methodType);
    }

    private void seedVerificationSession(UUID tenantId, UUID userId, UUID flowId) {
        jdbc.update(
                "INSERT INTO verification_sessions (id, user_id, tenant_id, flow_id, status, " +
                "current_step_number, started_at, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, 'PENDING', 0, ?, NOW(), NOW())",
                UUID.randomUUID(), userId, tenantId, flowId, Instant.now());
    }
}
