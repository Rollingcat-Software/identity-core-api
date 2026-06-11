package com.fivucsas.identity.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.domain.exception.TokenRevokedException;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RefreshTokenService}.
 *
 * <p>Covers BE-M5 (2026-04-19): createRefreshToken must NOT nuke every existing
 * active token for the user (broke multi-device sessions).
 *
 * <p>Covers P1-1 (2026-05-02): refresh-token secret-half is hashed at rest;
 * wire format is {@code <id>.<secret>}; dual-read fallback for legacy
 * plaintext tokens.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenService")
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private AuditLogPort auditLogPort;

    @Mock
    private RefreshTokenFamilyRevoker familyRevoker;

    @InjectMocks
    private RefreshTokenService service;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "refreshTokenDurationMs", 604_800_000L);
    }

    @Test
    @DisplayName("createRefreshToken does not revoke all existing user tokens [BE-M5]")
    void createRefreshToken_DoesNotRevokeAllUserTokens() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        service.createRefreshToken(user, "1.2.3.4", "JUnit");

        // BE-M5: the unconditional bulk-revoke was the broken behavior.
        verify(refreshTokenRepository, never()).revokeAllUserTokens(any(User.class), any());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("createRefreshToken mints <id>.<secret> wire token and stores SHA-256 of secret [P1-1]")
    void createRefreshToken_MintsHashedWireToken() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken minted = service.createRefreshToken(user, "1.2.3.4", "JUnit");

        // Wire format: <uuid>.<base64url-secret>
        String wire = minted.getToken();
        assertThat(wire).contains(".");
        int dot = wire.indexOf('.');
        UUID idPart = UUID.fromString(wire.substring(0, dot));
        String secret = wire.substring(dot + 1);
        assertThat(idPart).isEqualTo(minted.getId());
        assertThat(secret).isNotBlank();

        // The persisted hash equals sha256(secret).
        byte[] expected = RefreshTokenHasher.sha256(secret);
        assertThat(minted.getTokenSecretHash()).isEqualTo(expected);
    }

    @Test
    @DisplayName("findByToken: round-trip succeeds for newly-minted hashed token [P1-1]")
    void findByToken_HashedRoundTrip() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken minted = service.createRefreshToken(user, "1.2.3.4", "JUnit");
        when(refreshTokenRepository.findById(minted.getId())).thenReturn(Optional.of(minted));

        RefreshToken found = service.findByToken(minted.getToken());

        assertThat(found).isSameAs(minted);
    }

    @Test
    @DisplayName("findByToken: tampered secret rejected, no auto-revoke [P1-1]")
    void findByToken_TamperedSecret_RejectsWithoutRevoke() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken minted = service.createRefreshToken(user, "1.2.3.4", "JUnit");
        when(refreshTokenRepository.findById(minted.getId())).thenReturn(Optional.of(minted));
        // Tampered token: keep id, scramble secret.
        String tampered = minted.getId() + ".obviously-not-the-secret";

        assertThatThrownBy(() -> service.findByToken(tampered))
                .isInstanceOf(TokenRevokedException.class);

        // Wrong-secret-for-known-id is "not found", NOT "reuse" — family must
        // not be revoked here. Only verifyExpiration's revoked-token path
        // qualifies per RFC 6749 §10.4.
        verify(refreshTokenRepository, never()).revokeFamily(any(UUID.class), any(Instant.class));
    }

    @Test
    @DisplayName("findByToken: legacy plaintext token now rejected after V60 drop [T4-D]")
    void findByToken_LegacyPlaintextRejectedAfterV60() {
        // T4-D (2026-05-11, V60): the plaintext column + dual-read fallback
        // were dropped after the 7-day soak window closed (V55 shipped
        // 2026-05-02). A pre-V55 token (no '.' separator) now resolves to
        // TokenRevokedException — by 2026-05-11 every such row has rolled
        // off via the 7-day TTL.
        String legacyToken = UUID.randomUUID().toString();  // no '.'

        assertThatThrownBy(() -> service.findByToken(legacyToken))
                .isInstanceOf(TokenRevokedException.class);

        // The dropped JPA derived query must not be invoked.
        verifyNoMoreInteractions(refreshTokenRepository);
    }

    @Test
    @DisplayName("findByToken: malformed wire token (bad uuid) yields TokenRevokedException [T4-D]")
    void findByToken_MalformedWire_Rejected() {
        // After V60 there is no plaintext fallback. Malformed wire tokens
        // resolve directly to TokenRevokedException via the not-found path.
        String malformed = "not-a-uuid.anything";

        assertThatThrownBy(() -> service.findByToken(malformed))
                .isInstanceOf(TokenRevokedException.class);

        verify(refreshTokenRepository, never()).findById(any(UUID.class));
    }

    @Test
    @DisplayName("createRefreshToken(clientId): mint records the issuing OAuth2 client [API-2 / V85]")
    void createRefreshToken_BindsClientId() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken minted = service.createRefreshToken(user, "1.2.3.4", "JUnit", "marmara-bys-demo");

        assertThat(minted.getClientId()).isEqualTo("marmara-bys-demo");
    }

    @Test
    @DisplayName("createRefreshToken (3-arg): legacy mints stay client-unbound (null) [API-2 / V85]")
    void createRefreshToken_LegacyMintIsUnbound() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken minted = service.createRefreshToken(user, "1.2.3.4", "JUnit");

        assertThat(minted.getClientId()).isNull();
    }

    @Test
    @DisplayName("rotateRefreshToken: the rotated successor inherits the client binding [API-2 / V85]")
    void rotateRefreshToken_SuccessorStaysClientBound() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        // The presented (old) token was minted bound to client "app-a".
        RefreshToken old = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .familyId(UUID.randomUUID())
                .clientId("app-a")
                .tokenSecretHash(RefreshTokenHasher.sha256("secret"))
                .expiryDate(Instant.now().plusSeconds(3600))
                .build();

        RefreshToken successor = service.rotateRefreshToken(old, "1.2.3.4", "JUnit");

        // Binding carried through rotation; family preserved (reuse-detection).
        assertThat(successor.getClientId()).isEqualTo("app-a");
        assertThat(successor.getFamilyId()).isEqualTo(old.getFamilyId());
        // Old token revoked as part of rotation.
        assertThat(old.isRevoked()).isTrue();
    }

    @Test
    @DisplayName("rotateRefreshToken: an unbound (legacy null-client) token stays unbound [API-2 / V85]")
    void rotateRefreshToken_UnboundStaysUnbound() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("user@test.com");
        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken old = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .familyId(UUID.randomUUID())
                .clientId(null)
                .tokenSecretHash(RefreshTokenHasher.sha256("secret"))
                .expiryDate(Instant.now().plusSeconds(3600))
                .build();

        RefreshToken successor = service.rotateRefreshToken(old, "1.2.3.4", "JUnit");

        assertThat(successor.getClientId()).isNull();
    }
}
