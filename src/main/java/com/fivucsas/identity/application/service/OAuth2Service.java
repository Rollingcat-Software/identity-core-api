package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * OAuth 2.0 / OpenID Connect service handling authorization code flow.
 *
 * RFC compliance:
 * - RFC 6749 (OAuth 2.0 Authorization Framework)
 * - RFC 7636 (PKCE - Proof Key for Code Exchange)
 * - OpenID Connect Core 1.0 (ID Token claims, nonce, scopes)
 *
 * Responsibilities:
 * - Client validation (client_id + redirect_uri + secret)
 * - Authorization code generation (stored in Redis with 10-minute TTL per RFC 6749 Section 4.1.2)
 * - PKCE code_challenge / code_verifier validation
 * - Code exchange (validate code, generate tokens with proper OIDC claims)
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

    @Value("${app.base-url:https://api.fivucsas.com}")
    private String issuer;

    private static final String AUTH_CODE_PREFIX = "oauth2:code:";
    // RFC 6749 Section 4.1.2: authorization code MUST expire shortly, max 10 minutes recommended
    private static final Duration AUTH_CODE_TTL = Duration.ofMinutes(10);

    /**
     * Validates the client and redirect URI combination.
     * Redirect URI must exact-match a registered URI (RFC 6749 Section 3.1.2.3).
     *
     * @return the client if valid
     * @throws IllegalArgumentException if client or redirect URI is invalid
     */
    public OAuth2Client validateClient(String clientId, String redirectUri) {
        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client_id"));

        if (!client.isRedirectUriAllowed(redirectUri)) {
            throw new IllegalArgumentException("Invalid redirect_uri for client");
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
     * The code is stored in Redis with a 10-minute TTL (RFC 6749 Section 4.1.2).
     * Supports PKCE (RFC 7636): stores code_challenge and code_challenge_method.
     * Supports OIDC nonce: stored alongside the code for inclusion in ID token.
     *
     * @return the authorization code (cryptographically random)
     */
    public String generateAuthorizationCode(
            String userEmail, String clientId, String redirectUri, String scope,
            String nonce, String codeChallenge, String codeChallengeMethod) {
        String code = UUID.randomUUID().toString();
        // Store code metadata in Redis with pipe-delimited fields
        // Fields: userEmail|clientId|redirectUri|scope|nonce|codeChallenge|codeChallengeMethod
        String value = String.join("|",
                userEmail,
                clientId,
                redirectUri,
                scope != null ? scope : "",
                nonce != null ? nonce : "",
                codeChallenge != null ? codeChallenge : "",
                codeChallengeMethod != null ? codeChallengeMethod : "");
        redisTemplate.opsForValue().set(AUTH_CODE_PREFIX + code, value, AUTH_CODE_TTL);
        log.info("OAuth2 authorization code generated for user: {} client: {}", userEmail, clientId);
        return code;
    }

    /**
     * Backward-compatible overload without PKCE/nonce parameters.
     */
    public String generateAuthorizationCode(String userEmail, String clientId, String redirectUri, String scope) {
        return generateAuthorizationCode(userEmail, clientId, redirectUri, scope, null, null, null);
    }

    /**
     * Exchanges an authorization code for tokens.
     * Validates PKCE code_verifier if code_challenge was provided at authorization time.
     * Authorization codes are single-use (deleted from Redis immediately).
     *
     * @return map containing access_token, token_type, expires_in, id_token, scope
     * @throws IllegalArgumentException if code is invalid, expired, or validation fails
     */
    public Map<String, Object> exchangeCode(
            String code, String clientId, String redirectUri,
            String clientSecret, String codeVerifier) {
        String key = AUTH_CODE_PREFIX + code;
        String stored = redisTemplate.opsForValue().get(key);

        if (stored == null) {
            throw new IllegalArgumentException("Invalid or expired authorization code");
        }

        // Consume the code immediately (single-use per RFC 6749 Section 4.1.2)
        redisTemplate.delete(key);

        String[] parts = stored.split("\\|", -1);
        if (parts.length < 3) {
            throw new IllegalArgumentException("Corrupted authorization code data");
        }

        String userEmail = parts[0];
        String storedClientId = parts[1];
        String storedRedirectUri = parts[2];
        String storedScope = parts.length > 3 ? parts[3] : "";
        String storedNonce = parts.length > 4 ? parts[4] : "";
        String storedCodeChallenge = parts.length > 5 ? parts[5] : "";
        String storedCodeChallengeMethod = parts.length > 6 ? parts[6] : "";

        // Validate client_id matches
        if (!storedClientId.equals(clientId)) {
            throw new IllegalArgumentException("client_id mismatch");
        }

        // Validate redirect_uri matches (exact match per RFC 6749 Section 4.1.3)
        if (!storedRedirectUri.equals(redirectUri)) {
            throw new IllegalArgumentException("redirect_uri mismatch");
        }

        // PKCE validation (RFC 7636 Section 4.6)
        if (!storedCodeChallenge.isEmpty()) {
            if (codeVerifier == null || codeVerifier.isEmpty()) {
                throw new IllegalArgumentException("code_verifier is required (PKCE)");
            }
            if (!verifyCodeChallenge(codeVerifier, storedCodeChallenge, storedCodeChallengeMethod)) {
                throw new IllegalArgumentException("Invalid code_verifier (PKCE)");
            }
        }

        // Validate client secret (required for confidential clients)
        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client_id"));

        if (clientSecret != null && !clientSecret.isEmpty()) {
            if (!passwordEncoder.matches(clientSecret, client.getClientSecret())) {
                throw new IllegalArgumentException("Invalid client_secret");
            }
        } else if (storedCodeChallenge.isEmpty()) {
            // If no PKCE and no client_secret, this is a security risk
            // Confidential clients MUST authenticate; public clients MUST use PKCE
            log.warn("OAuth2 token request without client_secret or PKCE for client: {}", clientId);
        }

        // Find user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Generate access token
        Map<String, Object> claims = new HashMap<>();
        claims.put("tenant_id", user.getTenant().getId().toString());
        claims.put("type", "oauth2");
        claims.put("scope", storedScope);

        String accessToken = jwtService.generateToken(claims, userEmail);
        long expiresIn = jwtService.getExpirationMillis() / 1000;

        // Generate ID token with required OIDC claims (OpenID Connect Core Section 2)
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put("iss", issuer);
        idTokenClaims.put("sub", user.getId().toString());
        idTokenClaims.put("aud", clientId);
        idTokenClaims.put("iat", Instant.now().getEpochSecond());
        idTokenClaims.put("exp", Instant.now().plusMillis(jwtService.getExpirationMillis()).getEpochSecond());
        idTokenClaims.put("auth_time", Instant.now().getEpochSecond());
        idTokenClaims.put("type", "id_token");

        // Include nonce if provided (OIDC Core Section 3.1.2.1)
        if (!storedNonce.isEmpty()) {
            idTokenClaims.put("nonce", storedNonce);
        }

        // Standard OIDC claims based on requested scopes
        if (storedScope.contains("email")) {
            idTokenClaims.put("email", user.getEmail());
            idTokenClaims.put("email_verified", user.isEmailVerified());
        }
        if (storedScope.contains("profile")) {
            idTokenClaims.put("name", user.getFullName());
            idTokenClaims.put("given_name", user.getFirstName());
            idTokenClaims.put("family_name", user.getLastName());
        }
        if (storedScope.contains("phone") && user.getPhoneNumber() != null) {
            idTokenClaims.put("phone_number", user.getPhoneNumber());
            idTokenClaims.put("phone_number_verified", user.isPhoneVerified());
        }

        String idToken = jwtService.generateToken(idTokenClaims, userEmail);

        // Build response (RFC 6749 Section 5.1)
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", expiresIn);
        response.put("id_token", idToken);
        if (!storedScope.isEmpty()) {
            response.put("scope", storedScope);
        }

        log.info("OAuth2 tokens issued for user: {} client: {}", userEmail, clientId);
        return response;
    }

    /**
     * Backward-compatible overload without code_verifier.
     */
    public Map<String, Object> exchangeCode(String code, String clientId, String redirectUri, String clientSecret) {
        return exchangeCode(code, clientId, redirectUri, clientSecret, null);
    }

    /**
     * Verifies a PKCE code_verifier against the stored code_challenge.
     * Supports plain and S256 methods (RFC 7636 Section 4.2).
     */
    private boolean verifyCodeChallenge(String codeVerifier, String codeChallenge, String method) {
        if ("S256".equalsIgnoreCase(method) || method.isEmpty()) {
            // Default to S256 if method not specified (more secure)
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                return codeChallenge.equals(computed);
            } catch (NoSuchAlgorithmException e) {
                log.error("SHA-256 not available for PKCE verification", e);
                return false;
            }
        } else if ("plain".equalsIgnoreCase(method)) {
            return codeChallenge.equals(codeVerifier);
        }
        return false;
    }

    /**
     * Extracts user info claims from the access token.
     * Implements OIDC UserInfo endpoint (OpenID Connect Core Section 5.3).
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
