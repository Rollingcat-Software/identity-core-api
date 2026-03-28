package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;

/**
 * OAuth 2.0 service handling authorization code flow.
 *
 * Responsibilities:
 * - Client validation (client_id + redirect_uri + secret)
 * - Authorization code generation (random UUID, stored in Redis with 30s TTL)
 * - Code exchange (validate code, generate tokens using existing JWT infrastructure)
 * - Userinfo extraction from token
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2Service {

    private final OAuth2ClientRepositoryPort clientRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final StringRedisTemplate redisTemplate;
    private final PasswordEncoder passwordEncoder;

    private static final String AUTH_CODE_PREFIX = "oauth2:code:";
    private static final Duration AUTH_CODE_TTL = Duration.ofSeconds(30);

    /**
     * Validates the client and redirect URI combination.
     *
     * @return the client if valid
     * @throws IllegalArgumentException if client or redirect URI is invalid
     */
    public OAuth2Client validateClient(String clientId, String redirectUri) {
        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client_id: " + clientId));

        if (!client.isRedirectUriAllowed(redirectUri)) {
            throw new IllegalArgumentException("Invalid redirect_uri for client: " + redirectUri);
        }

        return client;
    }

    /**
     * Validates the requested scopes against the client's allowed scopes.
     *
     * @throws IllegalArgumentException if any scope is not allowed
     */
    public void validateScopes(OAuth2Client client, String scope) {
        if (scope != null && !scope.isBlank() && !client.areAllScopesAllowed(scope)) {
            throw new IllegalArgumentException("Requested scope is not allowed for this client");
        }
    }

    /**
     * Generates an authorization code for the given user and client.
     * The code is stored in Redis with a 30-second TTL.
     *
     * @return the authorization code (UUID)
     */
    public String generateAuthorizationCode(String userEmail, String clientId, String redirectUri, String scope) {
        String code = UUID.randomUUID().toString();
        // Store code metadata in Redis: userEmail|clientId|redirectUri|scope
        String value = String.join("|", userEmail, clientId, redirectUri, scope != null ? scope : "");
        redisTemplate.opsForValue().set(AUTH_CODE_PREFIX + code, value, AUTH_CODE_TTL);
        log.info("OAuth2 authorization code generated for user: {} client: {}", userEmail, clientId);
        return code;
    }

    /**
     * Exchanges an authorization code for tokens.
     *
     * @return map containing access_token, token_type, expires_in, refresh_token, id_token
     * @throws IllegalArgumentException if code is invalid, expired, or client mismatch
     */
    public Map<String, Object> exchangeCode(String code, String clientId, String redirectUri, String clientSecret) {
        String key = AUTH_CODE_PREFIX + code;
        String stored = redisTemplate.opsForValue().get(key);

        if (stored == null) {
            throw new IllegalArgumentException("Invalid or expired authorization code");
        }

        // Consume the code immediately (one-time use)
        redisTemplate.delete(key);

        String[] parts = stored.split("\\|", -1);
        if (parts.length < 3) {
            throw new IllegalArgumentException("Corrupted authorization code data");
        }

        String userEmail = parts[0];
        String storedClientId = parts[1];
        String storedRedirectUri = parts[2];

        // Validate client_id matches
        if (!storedClientId.equals(clientId)) {
            throw new IllegalArgumentException("client_id mismatch");
        }

        // Validate redirect_uri matches
        if (!storedRedirectUri.equals(redirectUri)) {
            throw new IllegalArgumentException("redirect_uri mismatch");
        }

        // Validate client secret
        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client_id"));

        if (clientSecret != null && !passwordEncoder.matches(clientSecret, client.getClientSecret())) {
            throw new IllegalArgumentException("Invalid client_secret");
        }

        // Find user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Generate tokens using existing JWT infrastructure
        Map<String, Object> claims = new HashMap<>();
        claims.put("tenant_id", user.getTenant().getId().toString());
        claims.put("type", "oauth2");

        String accessToken = jwtService.generateToken(claims, userEmail);
        long expiresIn = jwtService.getExpirationMillis() / 1000;

        // Generate ID token with OIDC claims
        Map<String, Object> idTokenClaims = new HashMap<>(claims);
        idTokenClaims.put("email", user.getEmail());
        idTokenClaims.put("name", user.getFullName());
        idTokenClaims.put("given_name", user.getFirstName());
        idTokenClaims.put("family_name", user.getLastName());
        idTokenClaims.put("email_verified", user.isEmailVerified());

        String idToken = jwtService.generateToken(idTokenClaims, userEmail);

        // Build response
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", expiresIn);
        response.put("id_token", idToken);
        // Note: refresh_token is not issued via OAuth2 code flow for security
        // Clients should use the token endpoint again with a new code

        log.info("OAuth2 tokens issued for user: {} client: {}", userEmail, clientId);
        return response;
    }

    /**
     * Extracts user info claims from the access token.
     *
     * @return map of OIDC standard claims
     */
    public Map<String, Object> getUserInfo(String accessToken) {
        String email = jwtService.extractEmail(accessToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.getId().toString());
        claims.put("email", user.getEmail());
        claims.put("email_verified", user.isEmailVerified());
        claims.put("name", user.getFullName());
        claims.put("given_name", user.getFirstName());
        claims.put("family_name", user.getLastName());
        if (user.getPhoneNumber() != null) {
            claims.put("phone_number", user.getPhoneNumber());
            claims.put("phone_number_verified", user.isPhoneVerified());
        }
        claims.put("updated_at", user.getUpdatedAt() != null ? user.getUpdatedAt().getEpochSecond() : null);

        return claims;
    }
}
