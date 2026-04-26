package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.domain.exception.PkceVerificationException;
import com.fivucsas.identity.domain.model.PkceFailureReason;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.JwtService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuth2ServiceTest {

    @Mock private OAuth2ClientRepositoryPort clientRepository;
    @Mock private UserRepository userRepository;
    @Mock private JwtService jwtService;
    @Mock private StringRedisTemplate redisTemplate;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks
    private OAuth2Service service;

    @Test
    void validateClient_WhenValidClient_ShouldReturnClient() {
        // given
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.isRedirectUriAllowed("https://example.com/callback")).thenReturn(true);
        when(clientRepository.findByClientIdAndActiveTrue("client-1")).thenReturn(Optional.of(client));

        // when
        OAuth2Client result = service.validateClient("client-1", "https://example.com/callback");

        // then
        assertThat(result).isEqualTo(client);
    }

    @Test
    void validateClient_WhenClientNotFound_ShouldThrowIllegalArgument() {
        // given
        when(clientRepository.findByClientIdAndActiveTrue("unknown")).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.validateClient("unknown", "https://example.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid client_id");
    }

    @Test
    void validateClient_WhenInvalidRedirectUri_ShouldThrowIllegalArgument() {
        // given
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.isRedirectUriAllowed("https://evil.com")).thenReturn(false);
        when(clientRepository.findByClientIdAndActiveTrue("client-1")).thenReturn(Optional.of(client));

        // when/then
        assertThatThrownBy(() -> service.validateClient("client-1", "https://evil.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid redirect_uri");
    }

    @Test
    void validateScopes_WhenScopesNotAllowed_ShouldThrowIllegalArgument() {
        // given
        OAuth2Client client = mock(OAuth2Client.class);
        when(client.areAllScopesAllowed("admin")).thenReturn(false);

        // when/then
        assertThatThrownBy(() -> service.validateScopes(client, "admin"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("scope is not allowed");
    }

    @Test
    void validateScopes_WhenNullOrBlankScope_ShouldNotThrow() {
        // given
        OAuth2Client client = mock(OAuth2Client.class);

        // when/then - should not throw
        service.validateScopes(client, null);
        service.validateScopes(client, "");
        service.validateScopes(client, "   ");
    }

    @Test
    void generateAuthorizationCode_ShouldStoreCodeInRedis() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        // when
        String code = service.generateAuthorizationCode(
                "user@test.com", "client-1", "https://example.com/cb", "openid");

        // then
        assertThat(code).isNotBlank();
        // BE-M1 (2026-04-19): payload is now JSON, not pipe-delimited.
        verify(valueOps).set(
                eq("oauth2:code:" + code),
                contains("\"userEmail\":\"user@test.com\""),
                any(Duration.class));
    }

    @Test
    void generateAuthorizationCode_WithPkceAndNonce_ShouldStoreAllFields() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        // when
        String code = service.generateAuthorizationCode(
                "user@test.com", "client-1", "https://example.com/cb", "openid",
                "test-nonce", "challenge123", "S256");

        // then
        assertThat(code).isNotBlank();
        // BE-M1 (2026-04-19): payload is JSON; assert each field present rather
        // than a fragile full-string match.
        verify(valueOps).set(
                eq("oauth2:code:" + code),
                argThat(v -> v.contains("\"userEmail\":\"user@test.com\"")
                        && v.contains("\"clientId\":\"client-1\"")
                        && v.contains("\"nonce\":\"test-nonce\"")
                        && v.contains("\"codeChallenge\":\"challenge123\"")
                        && v.contains("\"codeChallengeMethod\":\"S256\"")),
                any(Duration.class));
    }

    @Test
    void exchangeCode_WhenValidCode_ShouldReturnTokens() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("oauth2:code:test-code"))
                .thenReturn("user@test.com|client-1|https://cb.com|openid profile email|||");

        OAuth2Client client = mock(OAuth2Client.class);
        when(client.getClientSecret()).thenReturn("hashed-secret");
        when(clientRepository.findByClientIdAndActiveTrue("client-1")).thenReturn(Optional.of(client));
        when(passwordEncoder.matches("secret", "hashed-secret")).thenReturn(true);

        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(tenantId);
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.getFullName()).thenReturn("Test User");
        when(user.getFirstName()).thenReturn("Test");
        when(user.getLastName()).thenReturn("User");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getTenant()).thenReturn(tenant);
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        when(jwtService.generateToken(anyMap(), eq("user@test.com"))).thenReturn("access-jwt", "id-jwt");
        when(jwtService.getExpirationMillis()).thenReturn(3600000L);

        // when
        Map<String, Object> result = service.exchangeCode("test-code", "client-1", "https://cb.com", "secret");

        // then
        assertThat(result).containsEntry("access_token", "access-jwt");
        assertThat(result).containsEntry("token_type", "Bearer");
        assertThat(result).containsEntry("id_token", "id-jwt");
        assertThat(result).containsEntry("expires_in", 3600L);
        verify(redisTemplate).delete("oauth2:code:test-code");
    }

    @Test
    void exchangeCode_WhenCodeNotFound_ShouldThrowPkceVerification() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(null);

        // when/then — Phase D5a: classifies as CODE_NOT_FOUND so the controller
        // can audit-log + rate-limit by clientId. Wire-format response is still
        // invalid_grant in the controller layer.
        assertThatThrownBy(() -> service.exchangeCode("invalid", "client-1", "https://cb.com", null))
                .isInstanceOf(PkceVerificationException.class)
                .hasMessageContaining("Invalid or expired authorization code");
    }

    @Test
    void exchangeCode_WhenClientIdMismatch_ShouldThrowIllegalArgument() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("oauth2:code:code1"))
                .thenReturn("user@test.com|client-1|https://cb.com|openid|||");

        // when/then
        assertThatThrownBy(() -> service.exchangeCode("code1", "wrong-client", "https://cb.com", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("client_id mismatch");
    }

    @Test
    void exchangeCode_WhenRedirectUriMismatch_ShouldThrowIllegalArgument() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("oauth2:code:code1"))
                .thenReturn("user@test.com|client-1|https://cb.com|openid|||");

        // when/then
        assertThatThrownBy(() -> service.exchangeCode("code1", "client-1", "https://wrong.com", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redirect_uri mismatch");
    }

    @Test
    void exchangeCode_WhenPkceValid_ShouldSucceed() throws Exception {
        // given
        String codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("oauth2:code:pkce-code"))
                .thenReturn("user@test.com|client-1|https://cb.com|openid profile email||" + codeChallenge + "|S256");

        OAuth2Client client = mock(OAuth2Client.class);
        when(clientRepository.findByClientIdAndActiveTrue("client-1")).thenReturn(Optional.of(client));

        User user = mock(User.class);
        Tenant tenant = mock(Tenant.class);
        UUID userId = UUID.randomUUID();
        when(tenant.getId()).thenReturn(UUID.randomUUID());
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.getFullName()).thenReturn("Test User");
        when(user.getFirstName()).thenReturn("Test");
        when(user.getLastName()).thenReturn("User");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getTenant()).thenReturn(tenant);
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        when(jwtService.generateToken(anyMap(), eq("user@test.com"))).thenReturn("access-jwt", "id-jwt");
        when(jwtService.getExpirationMillis()).thenReturn(3600000L);

        // when
        Map<String, Object> result = service.exchangeCode(
                "pkce-code", "client-1", "https://cb.com", null, codeVerifier);

        // then
        assertThat(result).containsEntry("access_token", "access-jwt");
        verify(redisTemplate).delete("oauth2:code:pkce-code");
    }

    @Test
    void exchangeCode_WhenPkceInvalid_ShouldThrowPkceVerification() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("oauth2:code:pkce-code"))
                .thenReturn("user@test.com|client-1|https://cb.com|openid||validChallenge|S256");

        // when/then — Phase D5a: VERIFIER_MISMATCH carries clientId so the
        // controller can audit + rate-limit. Verifier value itself is NOT
        // attached to the exception.
        assertThatThrownBy(() -> service.exchangeCode(
                "pkce-code", "client-1", "https://cb.com", null, "wrong-verifier"))
                .isInstanceOf(PkceVerificationException.class)
                .hasMessageContaining("Invalid code_verifier");
    }

    @Test
    void exchangeCode_WhenPkceMissingVerifier_ShouldThrowPkceVerification() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get("oauth2:code:pkce-code"))
                .thenReturn("user@test.com|client-1|https://cb.com|openid||challenge|S256");

        // when/then
        assertThatThrownBy(() -> service.exchangeCode(
                "pkce-code", "client-1", "https://cb.com", null, null))
                .isInstanceOf(PkceVerificationException.class)
                .hasMessageContaining("code_verifier is required");
    }

    @Test
    void getUserInfo_WhenValidToken_ShouldReturnUserClaims() {
        // given
        when(jwtService.extractEmail("valid-token")).thenReturn("user@test.com");
        User user = mock(User.class);
        UUID userId = UUID.randomUUID();
        when(user.getId()).thenReturn(userId);
        when(user.getEmail()).thenReturn("user@test.com");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getFullName()).thenReturn("Test User");
        when(user.getFirstName()).thenReturn("Test");
        when(user.getLastName()).thenReturn("User");
        when(user.getPhoneNumber()).thenReturn(null);
        when(user.getUpdatedAt()).thenReturn(null);
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        // when
        Map<String, Object> claims = service.getUserInfo("valid-token");

        // then
        assertThat(claims).containsEntry("sub", userId.toString());
        assertThat(claims).containsEntry("email", "user@test.com");
        assertThat(claims).containsEntry("email_verified", true);
        assertThat(claims).containsEntry("name", "Test User");
    }

    @Test
    void getUserInfo_WhenUserNotFound_ShouldThrowIllegalArgument() {
        // given
        when(jwtService.extractEmail("token")).thenReturn("no@user.com");
        when(userRepository.findByEmail("no@user.com")).thenReturn(Optional.empty());

        // when/then
        assertThatThrownBy(() -> service.getUserInfo("token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("User not found");
    }
}
