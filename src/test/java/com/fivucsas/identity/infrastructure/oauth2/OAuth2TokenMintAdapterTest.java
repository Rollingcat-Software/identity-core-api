package com.fivucsas.identity.infrastructure.oauth2;

import com.fivucsas.identity.domain.exception.TenantSuspendedException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.JwtService;
import com.fivucsas.identity.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2TokenMintAdapter} — the infrastructure bridge that
 * builds the OAuth 2.0 / OIDC token-endpoint response. These assertions were
 * moved here from {@code OAuth2ServiceTest} when the {@code buildTokenResponse}
 * logic relocated from {@code OAuth2Service} (application layer) into this
 * adapter to satisfy the {@code UserDomainBoundaryTest} hexagonal boundary
 * (the application service must not touch {@code entity.User}). The token-shape
 * coverage is preserved verbatim — it just now exercises the layer that owns it.
 */
@ExtendWith(MockitoExtension.class)
class OAuth2TokenMintAdapterTest {

    @Mock private UserRepository userRepository;
    @Mock private JwtService jwtService;
    @Mock private RefreshTokenService refreshTokenService;

    private OAuth2TokenMintAdapter adapter;

    @BeforeEach
    void setUp() {
        // Real resolver with the pairwise flag OFF → sub == user.id (the default,
        // zero-behaviour-change path). PairwiseSubjectResolverTest covers flag-ON.
        PairwiseSubjectResolver resolver = new PairwiseSubjectResolver(false, "");
        adapter = new OAuth2TokenMintAdapter(
                userRepository, jwtService, refreshTokenService, resolver,
                "https://api.fivucsas.com");
    }

    private void stubRefreshTokenMint() {
        RefreshToken minted = mock(RefreshToken.class);
        when(minted.getToken()).thenReturn("refresh-wire-token");
        when(minted.getExpiryDate()).thenReturn(Instant.now().plus(Duration.ofDays(7)));
        // API-2 (V85): the authorization_code mint binds the issuing client, so the
        // adapter calls the 4-arg createRefreshToken(user, ip, ua, clientId) overload.
        when(refreshTokenService.createRefreshToken(any(), any(), any(), any())).thenReturn(minted);
    }

    private User mockUser(String email, Tenant tenant) {
        User user = mock(User.class);
        lenient().when(tenant.getId()).thenReturn(UUID.randomUUID());
        lenient().when(user.getId()).thenReturn(UUID.randomUUID());
        lenient().when(user.getEmail()).thenReturn(email);
        lenient().when(user.getFullName()).thenReturn("Test User");
        lenient().when(user.getFirstName()).thenReturn("Test");
        lenient().when(user.getLastName()).thenReturn("User");
        lenient().when(user.isEmailVerified()).thenReturn(true);
        when(user.getTenant()).thenReturn(tenant);
        return user;
    }

    @Test
    void mintForAuthorizationCode_WhenValidUser_ShouldReturnFullTokenResponse() {
        // given
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.getClientId()).thenReturn("client-1");
        User user = mockUser("user@test.com", mock(Tenant.class));
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(jwtService.generateToken(anyMap(), eq("user@test.com"))).thenReturn("access-jwt");
        when(jwtService.generateIdToken(anyMap(), eq("user@test.com"))).thenReturn("id-jwt");
        when(jwtService.getExpirationMillis()).thenReturn(3600000L);
        stubRefreshTokenMint();

        // when
        Map<String, Object> result = adapter.mintForAuthorizationCode(
                "user@test.com", client, "openid profile email", null, "1.2.3.4", "agent");

        // then
        assertThat(result).containsEntry("access_token", "access-jwt");
        assertThat(result).containsEntry("token_type", "Bearer");
        assertThat(result).containsEntry("id_token", "id-jwt");
        assertThat(result).containsEntry("expires_in", 3600L);
        // RFC 6749 §6: the authorization_code exchange also returns a refresh_token.
        assertThat(result).containsEntry("refresh_token", "refresh-wire-token");
        assertThat(result).containsKey("refresh_expires_in");

        // P1-5: the ID token is minted via generateIdToken (NOT generateToken,
        // which appends the API audience), aud/azp = the RP client_id only.
        ArgumentCaptor<Map<String, Object>> idClaims = ArgumentCaptor.forClass(Map.class);
        verify(jwtService).generateIdToken(idClaims.capture(), eq("user@test.com"));
        assertThat(idClaims.getValue()).containsEntry("aud", "client-1");
        assertThat(idClaims.getValue()).containsEntry("azp", "client-1");
        assertThat(idClaims.getValue()).containsEntry("type", "id_token");
        // The access-token path is the only generateToken() caller.
        verify(jwtService).generateToken(anyMap(), eq("user@test.com"));
        // API-2 (V85): the minted refresh token is bound to THIS client's wire id
        // so the refresh grant can later reject a cross-client replay.
        verify(refreshTokenService).createRefreshToken(
                any(), eq("1.2.3.4"), eq("agent"), eq("client-1"));
    }

    @Test
    void mintForAuthorizationCode_WhenUserNotFound_ShouldThrowIllegalArgument() {
        OAuth2Client client = mock(OAuth2Client.class);
        when(userRepository.findByEmail("nobody@test.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> adapter.mintForAuthorizationCode(
                "nobody@test.com", client, "openid", null, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    void mintForRefreshGrant_WhenTenantActive_ShouldMintAccessAndIdTokenWithoutRefresh() {
        // given
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.getClientId()).thenReturn("client-1");
        Tenant tenant = mock(Tenant.class);
        when(tenant.getStatus()).thenReturn(TenantStatus.ACTIVE);
        User user = mockUser("user@test.com", tenant);
        RefreshToken existing = mock(RefreshToken.class);
        when(existing.getUser()).thenReturn(user);
        when(jwtService.generateToken(anyMap(), eq("user@test.com"))).thenReturn("access-jwt");
        when(jwtService.generateIdToken(anyMap(), eq("user@test.com"))).thenReturn("id-jwt");
        when(jwtService.getExpirationMillis()).thenReturn(3600000L);

        // when
        Map<String, Object> result = adapter.mintForRefreshGrant(
                existing, client, "openid profile", "1.2.3.4", "agent");

        // then — access + id token present; the caller appends the rotated
        // refresh token, so this adapter must NOT mint one.
        assertThat(result).containsEntry("access_token", "access-jwt");
        assertThat(result).containsEntry("id_token", "id-jwt");
        assertThat(result).doesNotContainKey("refresh_token");
        // The refresh-grant adapter mints no refresh token (the caller rotates it),
        // so neither createRefreshToken overload is invoked here (API-2 4-arg incl.).
        verify(refreshTokenService, never()).createRefreshToken(any(), any(), any());
        verify(refreshTokenService, never()).createRefreshToken(any(), any(), any(), any());
    }

    @Test
    void mintForRefreshGrant_WhenTenantSuspended_ShouldThrowTenantSuspended() {
        OAuth2Client client = mock(OAuth2Client.class);
        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        when(tenant.getStatus()).thenReturn(TenantStatus.SUSPENDED);
        when(tenant.getId()).thenReturn(UUID.randomUUID());
        when(user.getTenant()).thenReturn(tenant);
        when(user.getEmail()).thenReturn("user@test.com");
        RefreshToken existing = mock(RefreshToken.class);
        when(existing.getUser()).thenReturn(user);

        assertThatThrownBy(() -> adapter.mintForRefreshGrant(
                existing, client, "openid", null, null))
                .isInstanceOf(TenantSuspendedException.class);

        verify(jwtService, never()).generateToken(anyMap(), any());
    }
}
