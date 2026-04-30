package com.fivucsas.identity.service;

import com.fivucsas.identity.application.dto.command.RegisterUserCommand;
import com.fivucsas.identity.application.dto.response.AuthenticationResponse;
import com.fivucsas.identity.application.service.RegisterUserService;
import com.fivucsas.identity.domain.exception.TokenRevokedException;
import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.AuditLogRepository;
import com.fivucsas.identity.repository.RefreshTokenRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration test for refresh-token rotation-family reuse-detection (Sec-P2 #6 fix).
 *
 * <p>Reproduces the rollback bug fixed by adding {@code noRollbackFor =
 * TokenRevokedException.class} to {@link RefreshTokenService#verifyExpiration}.
 * Before the fix, throwing TokenRevokedException would roll back the family
 * revocation row, leaving the attacker's "winning" token active and rendering
 * RFC 6749 §10.4 reuse-detection inert.
 *
 * <p>Scenario: a user has two refresh tokens in family A — the original
 * (already revoked, e.g. by rotation) and a child still active. Calling
 * verifyExpiration on the revoked token must:
 * <ol>
 *   <li>Throw TokenRevokedException (caller signal).</li>
 *   <li>Persist {@code revokeFamily(A)} so the active sibling is killed.</li>
 *   <li>Persist a {@code REFRESH_TOKEN_REUSE_DETECTED} audit log row.</li>
 * </ol>
 *
 * <p>Audit row was already in {@code Propagation.REQUIRES_NEW} so it survived
 * the parent rollback; the family revoke was the data-integrity bug.
 */
@SpringBootTest
@Testcontainers
@EnabledIfEnvironmentVariable(named = "RUN_INTEGRATION", matches = "true")
@ActiveProfiles("integration")
@DisplayName("RefreshTokenService — family revocation persistence on reuse-detection")
class RefreshTokenFamilyRevocationTest {

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

    private static final String TEST_EMAIL = "family.revoke.test@fivucsas.com";
    private static final String TEST_PASSWORD = "SecurePassword123!";

    @Autowired
    private RegisterUserService registerUserService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private UserRepository userRepository;

    @AfterEach
    void cleanUp() {
        userRepository.findByEmail(TEST_EMAIL).ifPresent(user -> {
            refreshTokenRepository.findByUser(user).forEach(refreshTokenRepository::delete);
            userRepository.delete(user);
        });
    }

    @Test
    @DisplayName("verifyExpiration on already-revoked token persists family revoke + audit row across throw")
    void verifyExpiration_ReusedToken_PersistsFamilyRevocationAndAudit() {
        // Arrange — create a user via the registration flow (mints first refresh token in family A)
        AuthenticationResponse register = registerUserService.execute(RegisterUserCommand.builder()
                .email(TEST_EMAIL)
                .password(TEST_PASSWORD)
                .firstName("Family")
                .lastName("Revoke")
                .ipAddress("127.0.0.1")
                .userAgent("JUnit")
                .build());
        assertThat(register).isNotNull();

        User user = userRepository.findByEmail(TEST_EMAIL).orElseThrow();

        // Original token in family A — mark revoked to simulate "already rotated once"
        RefreshToken original = refreshTokenRepository.findByToken(register.getRefreshToken()).orElseThrow();
        UUID familyId = original.getFamilyId();
        original.setRevoked(true);
        original.setRevokedAt(Instant.now());
        refreshTokenRepository.save(original);

        // Active sibling (the rotated child) in same family A — represents the
        // active credential that family-revoke must kill on reuse-detection.
        RefreshToken sibling = RefreshToken.builder()
                .user(user)
                .token("sibling-token-" + UUID.randomUUID())
                .familyId(familyId)
                .expiryDate(Instant.now().plusSeconds(3600))
                .ipAddress("127.0.0.1")
                .userAgent("JUnit")
                .isRevoked(false)
                .build();
        refreshTokenRepository.save(sibling);

        long auditCountBefore = auditLogRepository.count();

        // Act — replay the original (revoked) token. Service must throw, AND persist family revoke + audit row.
        assertThatThrownBy(() -> refreshTokenService.verifyExpiration(original))
                .isInstanceOf(TokenRevokedException.class);

        // Assert (1) — family revocation persisted across the throw (the bug we're fixing).
        RefreshToken siblingAfter = refreshTokenRepository.findById(sibling.getId()).orElseThrow();
        assertThat(siblingAfter.isRevoked())
                .as("Active sibling in family must be revoked even though verifyExpiration threw")
                .isTrue();
        assertThat(siblingAfter.getRevokedAt())
                .as("revokedAt timestamp must be set by revokeFamily")
                .isNotNull();

        // Assert (2) — no active tokens remain in the family.
        List<RefreshToken> remaining = refreshTokenRepository.findActiveTokensByUser(user, Instant.now())
                .stream()
                .filter(t -> familyId.equals(t.getFamilyId()))
                .toList();
        assertThat(remaining)
                .as("All family members must be revoked after reuse-detection")
                .isEmpty();

        // Assert (3) — REFRESH_TOKEN_REUSE_DETECTED audit row was written.
        // (Audit adapter uses REQUIRES_NEW so this always commits, but assert it explicitly
        // so a regression that drops the audit call is still caught.)
        long auditCountAfter = auditLogRepository.count();
        assertThat(auditCountAfter)
                .as("Audit log count must increase after reuse-detection")
                .isGreaterThan(auditCountBefore);

        boolean reuseEventPresent = auditLogRepository.findAll().stream()
                .map(AuditLog::getAction)
                .anyMatch("REFRESH_TOKEN_REUSE_DETECTED"::equals);
        assertThat(reuseEventPresent)
                .as("REFRESH_TOKEN_REUSE_DETECTED audit row must be present")
                .isTrue();
    }
}
