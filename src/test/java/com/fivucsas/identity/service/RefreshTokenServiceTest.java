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
        // Plaintext fallback must not have been used.
        verify(refreshTokenRepository, never()).findByToken(anyString());
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
        when(refreshTokenRepository.findByToken(tampered)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.findByToken(tampered))
                .isInstanceOf(TokenRevokedException.class);

        // Wrong-secret-for-known-id is "not found", NOT "reuse" — family must
        // not be revoked here. Only verifyExpiration's revoked-token path
        // qualifies per RFC 6749 §10.4.
        verify(refreshTokenRepository, never()).revokeFamily(any(UUID.class), any(Instant.class));
    }

    @Test
    @DisplayName("findByToken: legacy plaintext token still verifies via dual-read [P1-1]")
    void findByToken_LegacyPlaintext_FallsBack() {
        // Simulates a row minted before V55: tokenSecretHash is null and the
        // raw value has no `.` separator (UUID.toString — no dots).
        User user = mock(User.class);
        String legacyToken = UUID.randomUUID().toString();
        RefreshToken legacy = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .token(legacyToken)
                .familyId(UUID.randomUUID())
                .expiryDate(Instant.now().plusSeconds(3600))
                .build();
        when(refreshTokenRepository.findByToken(legacyToken)).thenReturn(Optional.of(legacy));

        RefreshToken found = service.findByToken(legacyToken);

        assertThat(found).isSameAs(legacy);
    }

    @Test
    @DisplayName("findByToken: malformed wire token (bad uuid) falls through to plaintext lookup")
    void findByToken_MalformedWire_FallsThrough() {
        String malformed = "not-a-uuid.anything";
        when(refreshTokenRepository.findByToken(malformed)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.findByToken(malformed))
                .isInstanceOf(TokenRevokedException.class);

        verify(refreshTokenRepository).findByToken(malformed);
        verify(refreshTokenRepository, never()).findById(any(UUID.class));
    }
}
