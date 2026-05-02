package com.fivucsas.identity.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.TokenRevokedException;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * F5 — Refresh-token family-revoke regression coverage.
 *
 * <p>Validates the rotation + reuse-detection chain that landed in PR #56
 * (Sec-P2 #6 + P1-1 hash-on-write). The existing {@link RefreshTokenServiceTest}
 * covers create-and-find dual-read, but does NOT cover what happens when a
 * client replays an already-rotated (revoked) token — that is the contract
 * this test exercises.</p>
 *
 * <p>Per RFC 6749 §10.4 + OAuth 2.0 Security BCP §4.13: presenting a revoked
 * refresh token must revoke EVERY token in its rotation family — including any
 * legitimate descendant minted by the user racing the attacker.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("F5 — RefreshTokenService family revocation")
class RefreshTokenFamilyRevocationTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private AuditLogPort auditLogPort;

    @InjectMocks
    private RefreshTokenService service;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "refreshTokenDurationMs", 604_800_000L);
    }

    @Nested
    @DisplayName("rotate() chain")
    class RotateChain {

        @Test
        @DisplayName("rotate revokes the old token and inherits the family_id")
        void rotate_revokesOld_inheritsFamily() {
            User user = stubUser();
            UUID familyId = UUID.randomUUID();
            RefreshToken oldToken = aPersistedToken(user, familyId, /*revoked*/ false);
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            RefreshToken rotated = service.rotateRefreshToken(oldToken, "1.2.3.4", "JUnit");

            // Old token revoked
            assertThat(oldToken.isRevoked()).isTrue();
            assertThat(oldToken.getRevokedAt()).isNotNull();
            // New token inherits family
            assertThat(rotated.getFamilyId()).isEqualTo(familyId);
            // Wire format new
            assertThat(rotated.getToken()).contains(".");
            assertThat(rotated.getId()).isNotEqualTo(oldToken.getId());
        }
    }

    @Nested
    @DisplayName("verifyExpiration() reuse-detection")
    class ReuseDetection {

        @Test
        @DisplayName("presenting a revoked token fans out revokeFamily across the chain")
        void revokedTokenReuse_revokesEntireFamily() {
            User user = stubUser();
            UUID familyId = UUID.randomUUID();
            RefreshToken revoked = aPersistedToken(user, familyId, /*revoked*/ true);
            // Repository reports 3 family members were live before bulk revoke.
            when(refreshTokenRepository.revokeFamily(eq(familyId), any(Instant.class)))
                    .thenReturn(3);

            assertThatThrownBy(() -> service.verifyExpiration(revoked))
                    .isInstanceOf(TokenRevokedException.class);

            verify(refreshTokenRepository).revokeFamily(eq(familyId), any(Instant.class));
            ArgumentCaptor<String> action = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<String> detail = ArgumentCaptor.forClass(String.class);
            verify(auditLogPort).logSecurityEvent(
                    eq(revoked.getUser().getId().toString()),
                    action.capture(),
                    any(),
                    detail.capture());
            assertThat(action.getValue()).isEqualTo("REFRESH_TOKEN_REUSE_DETECTED");
            assertThat(detail.getValue())
                    .contains("family=" + familyId)
                    .contains("revoked=3");
        }

        @Test
        @DisplayName("active token verifyExpiration returns the token without family side-effects")
        void activeToken_isPassThrough() {
            User user = stubUser();
            RefreshToken active = aPersistedToken(user, UUID.randomUUID(), /*revoked*/ false);

            RefreshToken result = service.verifyExpiration(active);

            assertThat(result).isSameAs(active);
            verify(refreshTokenRepository, never()).revokeFamily(any(UUID.class), any(Instant.class));
            verifyNoInteractions(auditLogPort);
        }
    }

    @Nested
    @DisplayName("dual-read legacy path interplay (P1-1)")
    class LegacyDualRead {

        @Test
        @DisplayName("legacy plaintext token still rotates correctly into the new wire format")
        void legacyToken_rotatesIntoHashedWire() {
            User user = stubUser();
            UUID legacyFamilyId = UUID.randomUUID();
            String legacyRaw = UUID.randomUUID().toString();   // pre-V55: no '.', no hash
            RefreshToken legacy = RefreshToken.builder()
                    .id(UUID.randomUUID())
                    .user(user)
                    .token(legacyRaw)
                    .familyId(legacyFamilyId)
                    .expiryDate(Instant.now().plusSeconds(3600))
                    .build();
            when(refreshTokenRepository.findByToken(legacyRaw)).thenReturn(Optional.of(legacy));
            when(refreshTokenRepository.save(any(RefreshToken.class)))
                    .thenAnswer(inv -> inv.getArgument(0));

            // Locate via dual-read
            RefreshToken found = service.findByToken(legacyRaw);
            // Then rotate — the new token must be hashed-wire and inherit the legacy family.
            RefreshToken rotated = service.rotateRefreshToken(found, "1.2.3.4", "JUnit");

            assertThat(rotated.getToken()).contains(".");
            assertThat(rotated.getTokenSecretHash()).isNotNull();
            assertThat(rotated.getFamilyId()).isEqualTo(legacyFamilyId);
            assertThat(legacy.isRevoked()).isTrue();
        }
    }

    // ── helpers ────────────────────────────────────────────────────────

    private static User stubUser() {
        User user = mock(User.class);
        // Both stubs lenient — not every test path reads them.
        lenient().when(user.getEmail()).thenReturn("user@test.com");
        lenient().when(user.getId()).thenReturn(UUID.randomUUID());
        return user;
    }

    private static RefreshToken aPersistedToken(User user, UUID familyId, boolean revoked) {
        RefreshToken rt = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .token(UUID.randomUUID() + ".secret-stub")
                .familyId(familyId)
                .expiryDate(Instant.now().plusSeconds(3600))
                .ipAddress("1.2.3.4")
                .build();
        if (revoked) {
            rt.revoke();
        }
        return rt;
    }
}
