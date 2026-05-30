package com.fivucsas.identity.multitenancy;

import com.fivucsas.identity.application.dto.command.VerifyBiometricCommand;
import com.fivucsas.identity.application.dto.response.BiometricResponse;
import com.fivucsas.identity.application.port.input.VerifyBiometricUseCase;
import com.fivucsas.identity.application.port.output.BiometricServicePort;
import com.fivucsas.identity.domain.exception.BiometricNotEnrolledException;
import com.fivucsas.identity.infrastructure.multitenancy.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Adversarial ISOLATION integration tests for the Model A (Phase 3) consent-gated
 * cross-tenant biometric verify path.
 *
 * <p>Scenarios (mirroring the P0-1 isolation IT philosophy — written to the SECURE
 * expectation, a failure is a real LEAK finding):
 * <ol>
 *   <li><b>(a)</b> Person enrolled in tenant A, NO consent for tenant B → a verify
 *       for that person's B-membership gets NO signal (identical to "not enrolled":
 *       {@link BiometricNotEnrolledException}); the bio store is never even called.</li>
 *   <li><b>(b)</b> After granting consent for B → the verify succeeds, routed to
 *       A's CANONICAL embedding (the bio call carries A's user_id + tenant_id).</li>
 *   <li><b>(c)</b> Revoke → back to NO signal.</li>
 *   <li><b>(d)</b> A DIFFERENT person/tenant cannot verify against this template —
 *       no canonical enrollment for their identity → NO signal.</li>
 * </ol>
 *
 * <p>The biometric-processor is NOT exercised (no ML container) — its port is a
 * {@link MockitoBean} that returns a positive verdict ONLY for the canonical
 * (user_id, tenant_id). This isolates the api ORCHESTRATION (consent gate +
 * canonical routing) which is the whole of the Phase 3 change. The bio store is
 * NOT re-keyed (Model A low-risk constraint), so routing correctness == passing
 * the canonical user_id to the unchanged bio verify.
 *
 * <p>Gated on {@code RUN_INTEGRATION=true} (Testcontainers / self-hosted runner),
 * matching the project's split-CI convention.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("Model A Phase 3 — consent-gated cross-tenant biometric verify isolation")
class IdentityBiometricConsentIT {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("fivucsas_consent_test")
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
    @Autowired private VerifyBiometricUseCase verifyBiometricUseCase;

    /** Bio store is keyed by user_id; the ML backend is stubbed. */
    @MockitoBean private BiometricServicePort biometricService;

    private UUID tenantA;          // where the person enrolled (canonical)
    private UUID tenantB;          // where the person ALSO has a membership
    private UUID identity;         // the ONE person spanning A + B
    private UUID userA;            // canonical membership (ENROLLED FACE)
    private UUID userB;            // B-membership (no local enrollment)

    private UUID otherIdentity;    // a DIFFERENT person
    private UUID otherUserB;       // their B-membership

    @BeforeEach
    void setUp() {
        tenantA = seedTenant("consent-a");
        tenantB = seedTenant("consent-b");

        identity = seedIdentity("Person One");
        userA = seedUser(tenantA, identity, "p1-a@" + tenantA + ".test");
        userB = seedUser(tenantB, identity, "p1-b@" + tenantB + ".test");
        // userB has its in-tenant enrollment flag OFF (no local FACE template).
        // userA holds the canonical ENROLLED FACE enrollment.
        seedEnrollment(tenantA, userA, "FACE", "ENROLLED");

        otherIdentity = seedIdentity("Person Two");
        otherUserB = seedUser(tenantB, otherIdentity, "p2-b@" + tenantB + ".test");

        // Bio stub: ONLY the canonical (userA, tenantA) verifies positively.
        Mockito.lenient().when(biometricService.verifyFace(any(UUID.class), any(), any(), any(), any()))
                .thenReturn(Map.of("verified", false, "message", "no match"));
        Mockito.lenient().when(biometricService.verifyFace(eq(userA), any(), eq(tenantA.toString()), any(), any()))
                .thenReturn(Map.of("verified", true, "message", "Face verified", "confidence", 0.97));
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        jdbc.update("DELETE FROM identity_tenant_biometric_consent WHERE identity_id IN (?, ?)",
                identity, otherIdentity);
        jdbc.update("DELETE FROM user_enrollments WHERE tenant_id IN (?, ?)", tenantA, tenantB);
        jdbc.update("DELETE FROM users WHERE tenant_id IN (?, ?)", tenantA, tenantB);
        jdbc.update("DELETE FROM identities WHERE id IN (?, ?)", identity, otherIdentity);
        jdbc.update("UPDATE tenants SET deleted_at = NOW() WHERE id IN (?, ?)", tenantA, tenantB);
    }

    @Test
    @DisplayName("(a) enrolled in A, NO consent for B → verify in B gets NO signal (not-enrolled)")
    void noConsent_noSignal() {
        assertThatThrownBy(() -> verifyBiometricUseCase.execute(verifyCmd(userB)))
                .isInstanceOf(BiometricNotEnrolledException.class);
        // The bio store must NOT be consulted — no leak that a template exists in A.
        Mockito.verify(biometricService, Mockito.never())
                .verifyFace(any(UUID.class), any(), any(), any(), any());
    }

    @Test
    @DisplayName("(b) after granting consent for B → verify succeeds against A's canonical template")
    void withConsent_routesToCanonical() {
        grantConsent(identity, tenantB, "FACE", true);

        BiometricResponse resp = verifyBiometricUseCase.execute(verifyCmd(userB));

        assertThat(resp.isSuccess()).isTrue();
        // Routed to the CANONICAL user_id + tenant_id, NOT userB / tenantB.
        Mockito.verify(biometricService).verifyFace(eq(userA), any(), eq(tenantA.toString()), any(), any());
        Mockito.verify(biometricService, Mockito.never())
                .verifyFace(eq(userB), any(), any(), any(), any());
    }

    @Test
    @DisplayName("(c) revoke consent → back to NO signal")
    void revoke_backToNoSignal() {
        grantConsent(identity, tenantB, "FACE", true);
        grantConsent(identity, tenantB, "FACE", false); // upsert → revoked

        assertThatThrownBy(() -> verifyBiometricUseCase.execute(verifyCmd(userB)))
                .isInstanceOf(BiometricNotEnrolledException.class);
        Mockito.verify(biometricService, Mockito.never())
                .verifyFace(any(UUID.class), any(), any(), any(), any());
    }

    @Test
    @DisplayName("(d) a DIFFERENT person cannot verify against this template, even with a B-consent for THEIR identity")
    void differentPerson_noAccess() {
        // Even if the OTHER person somehow has a consent row for B, they have no
        // canonical enrollment anywhere → NO signal.
        grantConsent(otherIdentity, tenantB, "FACE", true);

        assertThatThrownBy(() -> verifyBiometricUseCase.execute(verifyCmd(otherUserB)))
                .isInstanceOf(BiometricNotEnrolledException.class);
        Mockito.verify(biometricService, Mockito.never())
                .verifyFace(any(UUID.class), any(), any(), any(), any());
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private VerifyBiometricCommand verifyCmd(UUID userId) {
        return VerifyBiometricCommand.builder()
                .userId(userId.toString())
                .faceImage(null)
                .build();
    }

    private void grantConsent(UUID identityId, UUID tenantId, String method, boolean granted) {
        // Upsert mirroring the service (one row per identity/tenant/method).
        Integer updated = jdbc.update(
                "UPDATE identity_tenant_biometric_consent "
                + "SET granted = ?, granted_at = CASE WHEN ? THEN NOW() ELSE granted_at END, "
                + "revoked_at = CASE WHEN ? THEN NULL ELSE NOW() END, updated_at = NOW() "
                + "WHERE identity_id = ? AND tenant_id = ? AND method = ?",
                granted, granted, granted, identityId, tenantId, method);
        if (updated == 0) {
            jdbc.update(
                    "INSERT INTO identity_tenant_biometric_consent "
                    + "(id, identity_id, tenant_id, method, granted, granted_at, created_at, updated_at) "
                    + "VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN NOW() END, NOW(), NOW())",
                    UUID.randomUUID(), identityId, tenantId, method, granted, granted);
        }
    }

    private UUID seedTenant(String slug) {
        UUID id = UUID.randomUUID();
        // Unique name/slug per invocation — tearDown only soft-deletes (V53
        // forbids hard-delete) so a fixed name/slug collides on the next @Test.
        String unique = slug + "-" + id.toString().substring(0, 8);
        jdbc.update(
                "INSERT INTO tenants (id, name, slug, contact_email, status, max_users, "
                + "biometric_enabled, session_timeout_minutes, refresh_token_validity_days, "
                + "is_active, created_at, updated_at) "
                + "VALUES (?, ?, ?, ?, 'ACTIVE', 100, true, 30, 7, true, NOW(), NOW())",
                id, "CONSENT " + unique, unique, unique + "@example.com");
        return id;
    }

    private UUID seedIdentity(String displayName) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO identities (id, display_name, status, created_at, updated_at) "
                + "VALUES (?, ?, 'ACTIVE', NOW(), NOW())", id, displayName);
        return id;
    }

    private UUID seedUser(UUID tenantId, UUID identityId, String email) {
        UUID id = UUID.randomUUID();
        jdbc.update(
                "INSERT INTO users (id, tenant_id, identity_id, email, password_hash, first_name, "
                + "last_name, user_type, status, is_active, is_biometric_enrolled, created_at, updated_at) "
                + "VALUES (?, ?, ?, ?, '$2a$10$dummyhashfortesting.................................', "
                + "'C', 'Test', 'TENANT_MEMBER', 'ACTIVE', true, false, NOW(), NOW())",
                id, tenantId, identityId, email);
        return id;
    }

    private void seedEnrollment(UUID tenantId, UUID userId, String methodType, String status) {
        jdbc.update(
                "INSERT INTO user_enrollments (id, user_id, tenant_id, auth_method_type, status, "
                + "enrolled_at, created_at, updated_at) "
                + "VALUES (?, ?, ?, ?, ?, NOW(), NOW(), NOW())",
                UUID.randomUUID(), userId, tenantId, methodType, status);
    }
}
