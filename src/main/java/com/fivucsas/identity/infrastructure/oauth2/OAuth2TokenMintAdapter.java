package com.fivucsas.identity.infrastructure.oauth2;

import com.fivucsas.identity.application.port.output.OAuth2TokenMintPort;
import com.fivucsas.identity.domain.exception.TenantSuspendedException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.security.JwtService;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Infrastructure adapter for {@link OAuth2TokenMintPort} — the official bridge
 * that builds the OAuth 2.0 / OIDC token-endpoint response for
 * {@code OAuth2Service}.
 *
 * <p>Lives in {@code infrastructure..} (an {@code entity.User}-allowed package
 * per {@code UserDomainBoundaryTest}). It is the ONLY place the
 * {@code authorization_code} + {@code refresh_token} grants touch
 * {@code entity.User}: the application service hands over plain identifiers /
 * already-allowed entities ({@code OAuth2Client}, {@code RefreshToken}) and gets
 * back an entity-free {@link Map} token body.</p>
 *
 * <p>This is the SAME {@code buildTokenResponse} logic that previously lived in
 * {@code OAuth2Service}, moved verbatim so the token shape (access_token,
 * id_token claims, refresh_token wiring, OIDC scope filtering, pairwise subject)
 * is byte-identical. It reuses {@link JwtService} for the access + id tokens and
 * {@link RefreshTokenService} for the refresh token, mirroring the post-login
 * mint path used by {@code MembershipSwitchAdapter}.</p>
 */
@Component
@Slf4j
public class OAuth2TokenMintAdapter implements OAuth2TokenMintPort {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final PairwiseSubjectResolver pairwiseSubjectResolver;
    private final String issuer;

    public OAuth2TokenMintAdapter(
            UserRepository userRepository,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            PairwiseSubjectResolver pairwiseSubjectResolver,
            @Value("${app.base-url:https://api.fivucsas.com}") String issuer) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.pairwiseSubjectResolver = pairwiseSubjectResolver;
        this.issuer = issuer;
    }

    @Override
    @Transactional
    public Map<String, Object> mintForAuthorizationCode(
            String userEmail, OAuth2Client client, String scope, String nonce,
            String ipAddress, String userAgent) {

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return buildTokenResponse(user, client, scope, nonce, true, ipAddress, userAgent);
    }

    @Override
    @Transactional
    public Map<String, Object> mintForRefreshGrant(
            RefreshToken existing, OAuth2Client client, String scope,
            String ipAddress, String userAgent) {

        User user = existing.getUser();

        // Parity with RefreshAccessTokenService (P0-#8): refuse to mint a fresh
        // access token when the user's tenant is no longer ACTIVE — otherwise a
        // session active at suspension time could be kept alive indefinitely by
        // refreshing. The controller maps the suspension to invalid_grant.
        if (user.getTenant() != null
                && user.getTenant().getStatus() != TenantStatus.ACTIVE) {
            log.warn("OAuth2 refresh refused — tenant not active, userEmail={}, tenantId={}, tenantStatus={}",
                    user.getEmail(), user.getTenant().getId(), user.getTenant().getStatus());
            throw new TenantSuspendedException(user.getTenant().getStatus());
        }

        // The caller (OAuth2Service) rotates the presented token and appends the
        // rotated refresh_token + refresh_expires_in, so we mint the access +
        // id token portion only here (mintRefreshToken=false).
        return buildTokenResponse(user, client, scope, null, false, ipAddress, userAgent);
    }

    /**
     * Builds the RFC 6749 §5.1 token-endpoint success body: {@code access_token},
     * {@code token_type}, {@code expires_in}, {@code id_token}, optional
     * {@code scope}, and — when {@code mintRefreshToken} is true — a
     * {@code refresh_token} (RFC 6749 §6) plus {@code refresh_expires_in}.
     *
     * <p>Shared by the {@code authorization_code} exchange and the
     * {@code refresh_token} grant so both grants emit a byte-identical token shape.
     * The refresh token is minted through {@link RefreshTokenService#createRefreshToken}
     * — the SAME hashed/family/reuse-detection infra the legacy {@code /auth/refresh}
     * path uses; the raw wire value is read once from the transient
     * {@link RefreshToken#getToken()} and never persisted.</p>
     */
    private Map<String, Object> buildTokenResponse(
            User user, OAuth2Client client, String scope, String nonce,
            boolean mintRefreshToken, String ipAddress, String userAgent) {

        String userEmail = user.getEmail();
        String clientId = client.getClientId();
        String safeScope = scope == null ? "" : scope;
        String safeNonce = nonce == null ? "" : nonce;

        // Generate access token
        Map<String, Object> claims = new HashMap<>();
        claims.put("tenant_id", user.getTenant().getId().toString());
        claims.put("type", "oauth2");
        claims.put("scope", safeScope);
        // Phase 4: stamp the relying party so /userinfo can reproduce the SAME
        // pairwise `sub` as the id_token (the userinfo subject MUST equal the
        // id_token subject — OIDC Core §5.3.2). Harmless when the flag is off.
        claims.put("client_id", clientId);

        String accessToken = jwtService.generateToken(claims, userEmail);
        long expiresIn = jwtService.getExpirationMillis() / 1000;

        // Generate ID token with required OIDC claims (OpenID Connect Core Section 2)
        Map<String, Object> idTokenClaims = new HashMap<>();
        idTokenClaims.put("iss", issuer);
        // Phase 4: subject is identity-pairwise per RP when the flag is on; legacy
        // user.id otherwise (default). The resolver owns the entity.User access.
        idTokenClaims.put("sub", pairwiseSubjectResolver.resolveSubject(user, client));
        // P1-5 (2026-06-02): the ID token audience is the RP client_id ONLY.
        // Previously generateToken() also appended the API audience
        // (fivucsas-api), so the id_token shipped aud=[clientId, fivucsas-api];
        // a strict OIDC RP that asserts aud == its own client_id rejects a
        // multi-audience token unless an azp is present. We now (a) mint via
        // generateIdToken() which does NOT inject the API audience, and (b)
        // stamp azp=clientId (OIDC Core §2: REQUIRED when aud has a single
        // entry that is the RP, RECOMMENDED otherwise — always-present is safe
        // and what RPs expect).
        idTokenClaims.put("aud", clientId);
        idTokenClaims.put("azp", clientId);
        idTokenClaims.put("iat", Instant.now().getEpochSecond());
        idTokenClaims.put("exp", Instant.now().plusMillis(jwtService.getExpirationMillis()).getEpochSecond());
        idTokenClaims.put("auth_time", Instant.now().getEpochSecond());
        idTokenClaims.put("type", "id_token");

        // Include nonce if provided (OIDC Core Section 3.1.2.1)
        if (!safeNonce.isEmpty()) {
            idTokenClaims.put("nonce", safeNonce);
        }

        // Standard OIDC claims based on requested scopes
        if (safeScope.contains("email")) {
            idTokenClaims.put("email", user.getEmail());
            idTokenClaims.put("email_verified", user.isEmailVerified());
        }
        if (safeScope.contains("profile")) {
            idTokenClaims.put("name", user.getFullName());
            idTokenClaims.put("given_name", user.getFirstName());
            idTokenClaims.put("family_name", user.getLastName());
        }
        if (safeScope.contains("phone") && user.getPhoneNumber() != null) {
            idTokenClaims.put("phone_number", user.getPhoneNumber());
            idTokenClaims.put("phone_number_verified", user.isPhoneVerified());
        }

        // P1-5: generateIdToken skips the access-token (fivucsas-api) audience
        // so the RP-only aud set above survives as the sole audience.
        String idToken = jwtService.generateIdToken(idTokenClaims, userEmail);

        // Build response (RFC 6749 Section 5.1)
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", expiresIn);
        response.put("id_token", idToken);

        if (mintRefreshToken) {
            // RFC 6749 §6: issue a refresh token. createRefreshToken returns an
            // entity whose @Transient `token` field carries the raw wire value
            // (<id>.<secret>) exactly once — read it here, never persist it.
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, ipAddress, userAgent);
            response.put("refresh_token", refreshToken.getToken());
            long refreshExpiresIn =
                    Duration.between(Instant.now(), refreshToken.getExpiryDate()).getSeconds();
            response.put("refresh_expires_in", refreshExpiresIn);
        }

        if (!safeScope.isEmpty()) {
            response.put("scope", safeScope);
        }
        return response;
    }
}
