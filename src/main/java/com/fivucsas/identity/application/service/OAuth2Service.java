package com.fivucsas.identity.application.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.domain.exception.OAuth2Exception;
import com.fivucsas.identity.domain.exception.PkceVerificationException;
import com.fivucsas.identity.domain.model.PkceFailureReason;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.security.JwtService;
import com.fivucsas.identity.service.RefreshTokenService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
@Transactional(readOnly = true)
public class OAuth2Service {

    private final OAuth2ClientRepositoryPort clientRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final StringRedisTemplate redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final MfaSessionRepository mfaSessionRepository;
    private final com.fivucsas.identity.security.RateLimitService rateLimitService;
    // RFC 6749 §6: mints / rotates / validates refresh tokens. Same hashed
    // wire-format + rotation-family + reuse-detection infra the legacy
    // /auth/refresh path uses (RefreshAccessTokenService) — see refreshAccessToken below.
    private final RefreshTokenService refreshTokenService;
    // Phase 4 (flag-gated, default OFF): resolves the OIDC `sub` for id_token +
    // userinfo. With app.identity.oidc-subject-identity=false this returns the
    // legacy user.id; with it on, a pairwise pseudonym per relying party.
    private final com.fivucsas.identity.infrastructure.oauth2.PairwiseSubjectResolver pairwiseSubjectResolver;
    // Mints the token-endpoint response body (access_token + id_token + refresh).
    // The infrastructure adapter behind this port is the ONLY place the
    // authorization_code / refresh_token grants touch entity.User, keeping this
    // application service clean of the UserDomainBoundaryTest-fenced JPA type.
    private final com.fivucsas.identity.application.port.output.OAuth2TokenMintPort tokenMintPort;

    /**
     * API-2 kill-switch (V85): when true (default), the {@code refresh_token} grant
     * REJECTS a presented refresh token whose recorded issuing {@code client_id} is
     * non-null AND differs from the requesting client — so a token issued to app A
     * cannot be replayed by app B and reissued scoped to B. Legacy null-client
     * tokens are always accepted (grace window). Flip to {@code false} via
     * {@code APP_OAUTH2_REFRESH_TOKEN_CLIENT_BINDING_ENFORCED=false} to instantly
     * restore the legacy wire-value-only behavior with no redeploy.
     */
    @Value("${app.oauth2.refresh-token.client-binding-enforced:true}")
    private boolean refreshTokenClientBindingEnforced;

    private static final String AUTH_CODE_PREFIX = "oauth2:code:";
    // RFC 6749 Section 4.1.2: authorization code MUST expire shortly, max 10 minutes recommended
    private static final Duration AUTH_CODE_TTL = Duration.ofMinutes(10);

    // BE-M1 (2026-04-19): Redis auth-code metadata is now JSON. The legacy pipe
    // format is still tolerated on read for in-flight codes written before deploy,
    // then re-serialized on next write. Remove the pipe fallback after the auth
    // code TTL (10 min) has elapsed post-deploy — earliest cleanup 2026-04-19 +15m.
    // TODO(2026-04-19 +15m / 2026-04-19 03:15Z): delete legacy pipe parser below.
    private static final ObjectMapper AUTH_CODE_MAPPER = new ObjectMapper();

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
        // BE-M1 (2026-04-19): serialize as JSON — Jackson safely escapes pipes,
        // brackets, and quotes in any field. Previously pipe-delimited; a pipe
        // in any value corrupted parse boundaries.
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("userEmail", userEmail);
        payload.put("clientId", clientId);
        payload.put("redirectUri", redirectUri);
        payload.put("scope", scope != null ? scope : "");
        payload.put("nonce", nonce != null ? nonce : "");
        payload.put("codeChallenge", codeChallenge != null ? codeChallenge : "");
        payload.put("codeChallengeMethod", codeChallengeMethod != null ? codeChallengeMethod : "");
        String value;
        try {
            value = AUTH_CODE_MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            // Should never happen for a Map<String,String> — fail closed rather than
            // silently fall back to the legacy pipe encoding.
            log.error("OAuth2 auth-code JSON serialization failed", e);
            throw new IllegalStateException("Failed to serialize authorization code metadata", e);
        }
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
     * Atomic "consume MFA session and mint authorization code" critical section
     * for the hosted-login {@code POST /oauth2/authorize/complete} endpoint.
     *
     * <p>All three steps run inside the same transaction, so a failure between
     * consume and mint rolls back the consume and the session can be retried
     * (rather than being left poisoned in {@code consumed=true}-but-no-code state).
     * On success the session row is deleted so the same MFA can never mint a
     * second code.</p>
     *
     * <p>Quality batch P1-Q9 (review 2026-05-01): the {@code @Transactional}
     * boundary used to live on {@code OAuth2Controller.authorizeComplete};
     * moved here so the controller stays HTTP-only. Behaviour is unchanged —
     * the consume/mint/delete order, the audit-log lines, and the JSON
     * response shape mirror the previous controller body.</p>
     *
     * @param session   the {@link MfaSession} resolved from the bearer token
     * @param user      the user the session authenticates
     * @param clientId  validated OAuth2 client id
     * @param redirectUri validated redirect URI
     * @param scope     requested scope (defaulted by caller if blank)
     * @param nonce     OIDC nonce (nullable)
     * @param codeChallenge PKCE challenge (nullable)
     * @param codeChallengeMethod PKCE method (nullable)
     * @return the freshly minted single-use authorization code
     */
    @Transactional
    public String consumeMfaSessionAndMintCode(
            MfaSession session,
            User user,
            String clientId,
            String redirectUri,
            String scope,
            String nonce,
            String codeChallenge,
            String codeChallengeMethod) {

        // Mark consumed BEFORE minting the code so a crash between consume and mint
        // leaves the session poisoned (still marked consumed) and the transaction
        // rolls back the consume with the mint.
        session.consume();
        mfaSessionRepository.save(session);

        String code = generateAuthorizationCode(
                user.getEmail(), clientId, redirectUri,
                scope == null ? "openid profile email" : scope,
                nonce, codeChallenge, codeChallengeMethod);

        // Burn the MFA session record so it can't be replayed for a second code.
        // Runs inside the same @Transactional — delete + consume + code mint all
        // commit or rollback together.
        mfaSessionRepository.delete(session);

        log.info("OAuth2 hosted code minted — userId={}, clientId={}", user.getId(), clientId);
        return code;
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
        return exchangeCode(code, clientId, redirectUri, clientSecret, codeVerifier, null, null);
    }

    /**
     * Code-exchange overload that records the caller IP / User-Agent on the
     * refresh token minted for the issued session (RFC 6749 §6 audit trail).
     */
    public Map<String, Object> exchangeCode(
            String code, String clientId, String redirectUri,
            String clientSecret, String codeVerifier, String ipAddress, String userAgent) {
        String key = AUTH_CODE_PREFIX + code;
        String stored = redisTemplate.opsForValue().get(key);

        if (stored == null) {
            // Phase D5a: distinguish "never issued / TTL expired" from "already
            // consumed". Both manifest as Redis null because the consume path
            // deletes the key, so we cannot tell from this side which it was.
            // We classify as CODE_NOT_FOUND — the controller's audit row will
            // show clientId, and a spike of these from the same clientId still
            // surfaces a replay/brute-force pattern even without the finer split.
            throw new PkceVerificationException(clientId, PkceFailureReason.CODE_NOT_FOUND,
                    "Invalid or expired authorization code");
        }

        // Consume the code immediately (single-use per RFC 6749 Section 4.1.2)
        redisTemplate.delete(key);

        // BE-M1 (2026-04-19): prefer JSON; fall back to legacy pipe-split for
        // in-flight codes written by the previous build. The fallback can be
        // removed after 2026-04-19 +15m (AUTH_CODE_TTL + margin).
        String userEmail;
        String storedClientId;
        String storedRedirectUri;
        String storedScope;
        String storedNonce;
        String storedCodeChallenge;
        String storedCodeChallengeMethod;
        if (!stored.isEmpty() && stored.charAt(0) == '{') {
            try {
                @SuppressWarnings("unchecked")
                Map<String, String> payload = AUTH_CODE_MAPPER.readValue(stored, Map.class);
                userEmail = payload.getOrDefault("userEmail", "");
                storedClientId = payload.getOrDefault("clientId", "");
                storedRedirectUri = payload.getOrDefault("redirectUri", "");
                storedScope = payload.getOrDefault("scope", "");
                storedNonce = payload.getOrDefault("nonce", "");
                storedCodeChallenge = payload.getOrDefault("codeChallenge", "");
                storedCodeChallengeMethod = payload.getOrDefault("codeChallengeMethod", "");
            } catch (JsonProcessingException e) {
                throw new PkceVerificationException(clientId, PkceFailureReason.CORRUPT_DATA,
                        "Corrupted authorization code data");
            }
        } else {
            // Legacy path — log once and re-encode next mint will land as JSON.
            log.warn("OAuth2 auth-code using legacy pipe encoding — remove fallback after deploy +15m");
            String[] parts = stored.split("\\|", -1);
            if (parts.length < 3) {
                throw new PkceVerificationException(clientId, PkceFailureReason.CORRUPT_DATA,
                        "Corrupted authorization code data");
            }
            userEmail = parts[0];
            storedClientId = parts[1];
            storedRedirectUri = parts[2];
            storedScope = parts.length > 3 ? parts[3] : "";
            storedNonce = parts.length > 4 ? parts[4] : "";
            storedCodeChallenge = parts.length > 5 ? parts[5] : "";
            storedCodeChallengeMethod = parts.length > 6 ? parts[6] : "";
        }

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
                throw new PkceVerificationException(clientId, PkceFailureReason.MISSING_VERIFIER,
                        "code_verifier is required (PKCE)");
            }
            if (!verifyCodeChallenge(codeVerifier, storedCodeChallenge, storedCodeChallengeMethod)) {
                throw new PkceVerificationException(clientId, PkceFailureReason.VERIFIER_MISMATCH,
                        "Invalid code_verifier (PKCE)");
            }
        }

        // Validate client secret (required for confidential clients)
        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client_id"));

        // P0-SEC-2 (2026-05-02): RFC 6749 §2.3.1 — confidential clients MUST
        // authenticate to the token endpoint regardless of PKCE state. The
        // previous shape ("if clientSecret-present check, else if confidential
        // AND verifier-empty reject") let an attacker who replayed a stolen
        // code+code_verifier (both transit the user agent) skip the secret
        // check entirely on a confidential client. PKCE is *not* a substitute
        // for client authentication — it only proves the same UA that started
        // the flow finished it.
        if (client.isConfidential()) {
            if (clientSecret == null || clientSecret.isEmpty()
                    || !matchesCurrentOrPreviousSecret(client, clientSecret)) {
                throw new OAuth2Exception(HttpStatus.UNAUTHORIZED,
                        "client_secret required for confidential client");
            }
        } else if (clientSecret != null && !clientSecret.isEmpty()) {
            // Public client supplied a client_secret. If it doesn't match,
            // reject — the caller clearly intended to authenticate.
            if (!matchesCurrentOrPreviousSecret(client, clientSecret)) {
                throw new IllegalArgumentException("Invalid client_secret");
            }
        } else {
            // SECURITY_REVIEW_2026-05-01 §P2-2: public client with neither a
            // client_secret nor a code_verifier. RFC 7636 §4.4.1 mandates PKCE
            // for public clients on the token endpoint. The previous shape
            // logged a warn and fell through, so any pre-V34 public client
            // could redeem a code without proving it owned the original
            // /authorize request. Hard-reject with 400.
            if (codeVerifier == null || codeVerifier.isEmpty()) {
                log.warn("OAuth2 token request rejected — public client without code_verifier: {}", clientId);
                throw new OAuth2Exception(HttpStatus.BAD_REQUEST,
                        "code_verifier required for public client");
            }
            // codeVerifier present but storedCodeChallenge was empty (i.e. the
            // /authorize request never set a challenge). We still reject:
            // a verifier without a stored challenge can't be matched and the
            // request is malformed.
            if (storedCodeChallenge.isEmpty()) {
                log.warn("OAuth2 token request rejected — public client supplied code_verifier "
                        + "but authorization code has no code_challenge: {}", clientId);
                throw new OAuth2Exception(HttpStatus.BAD_REQUEST,
                        "code_verifier supplied but no code_challenge was registered at /authorize");
            }
        }

        // INVESTIGATION_MASTER_2026-05-07 §"developer/tenant constraints":
        // per-tenant /oauth2/token success-path rate limit. Charged AFTER
        // PKCE + secret validation succeeds so only legitimate mints count.
        // Tenant id is taken from the OAuth2Client (the integration owning
        // the client_id), not the user — a single tenant's client may mint
        // tokens for users from any tenant the client targets, but the
        // throttle is on the integration's tenant pool.
        String rateLimitTenantId = client.getTenant() != null
                ? client.getTenant().getId().toString()
                : null;
        if (rateLimitTenantId != null && !rateLimitService.allowTenantTokenMint(rateLimitTenantId)) {
            long retryAfter = rateLimitService.getSecondsUntilRefill(
                    rateLimitTenantId,
                    com.fivucsas.identity.security.RateLimitService.RateLimitType.TENANT_TOKEN);
            throw new TenantTokenRateLimitException(retryAfter);
        }

        // Build the access_token + id_token (+ a freshly minted refresh_token).
        // RFC 6749 §5.1 success body. Refresh token issuance (§6) is mirrored from
        // the legacy /auth/login + /auth/refresh path (RefreshTokenService) so the
        // hashed wire-format, rotation family, and reuse-detection are identical.
        // The resource owner is resolved + the response built inside the
        // infrastructure adapter (the only place entity.User is touched), keeping
        // this service boundary-clean (UserDomainBoundaryTest).
        Map<String, Object> response = tokenMintPort.mintForAuthorizationCode(
                userEmail, client, storedScope, storedNonce, ipAddress, userAgent);

        log.info("OAuth2 tokens issued for user: {} client: {}", userEmail, clientId);
        return response;
    }

    /**
     * RFC 6749 §6 — {@code grant_type=refresh_token}.
     *
     * <p>Validates the presented refresh token, ROTATES it (revokes the old,
     * mints a successor in the same rotation family), and issues a fresh
     * {@code access_token} + {@code id_token} + the rotated {@code refresh_token}.
     * Mirrors the legacy {@link com.fivucsas.identity.application.service.RefreshAccessTokenService}:
     * lookup by the presented wire value, expiry/revocation/reuse checks, then
     * rotation. An invalid / expired / reused / already-rotated token surfaces as
     * {@link TokenExpiredException} / {@link TokenRevokedException}, which the
     * controller maps to RFC 6749 {@code 400 invalid_grant}.</p>
     *
     * @param presentedRefreshToken the raw refresh_token from the request body
     * @param clientId              the requesting client (for scope binding + audit)
     * @param ipAddress             caller IP recorded on the rotated token
     * @param userAgent             caller User-Agent recorded on the rotated token
     * @return the RFC 6749 §5.1 token response with a rotated refresh_token
     */
    @Transactional
    public Map<String, Object> refreshAccessToken(
            String presentedRefreshToken, String clientId, String ipAddress, String userAgent) {

        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid client_id"));

        // Resolve + validate the presented token the SAME way /auth/refresh does:
        // findByToken hashes the wire value and matches the row; verifyExpiration
        // throws on expired (TokenExpiredException) or revoked/reused
        // (TokenRevokedException, after family-wide revoke per RFC 6749 §10.4).
        RefreshToken existing = refreshTokenService.findByToken(presentedRefreshToken);
        refreshTokenService.verifyExpiration(existing);

        // API-2 (V85): refuse a cross-client replay. A refresh token minted for
        // app A's client (existing.clientId == A) presented by app B's client
        // (clientId == B) is reissued scoped to B unless we reject it here. We
        // only reject when the token CARRIES a binding (non-null) and it differs
        // from the requesting client — legacy null-client tokens (the non-OAuth
        // /auth/login + /auth/refresh path, or pre-V85 rows) are accepted so the
        // existing login/refresh flow keeps working (grace window). Gated by the
        // client-binding-enforced kill-switch so it reverts via env with no
        // redeploy. The controller maps invalid_grant from this exception. Checked
        // BEFORE the mint/rotation so a mismatched replay never reissues a token —
        // and it reads only the token's recorded client_id (no entity.User touch),
        // keeping this service boundary-clean (UserDomainBoundaryTest).
        if (refreshTokenClientBindingEnforced
                && existing.getClientId() != null
                && !existing.getClientId().equals(clientId)) {
            log.warn("OAuth2 refresh refused — client mismatch: token bound to client={}, presented by client={}",
                    existing.getClientId(), clientId);
            throw new com.fivucsas.identity.domain.exception.TokenRevokedException(
                    "Refresh token was not issued to this client");
        }

        // Re-issue access + id tokens. The granted scope is the client's full
        // allowed scope set (RFC 6749 §6 permits a narrower scope, but never
        // broader; we re-grant what the client is registered for). Resolving the
        // resource owner, the tenant-active guard (parity with the legacy
        // /auth/refresh path — a suspended tenant cannot keep a session alive by
        // refreshing) and building the body all happen inside the infrastructure
        // adapter (the only place entity.User is touched), keeping this service
        // boundary-clean (UserDomainBoundaryTest).
        String grantedScope = client.getAllowedScopes() == null ? "" : client.getAllowedScopes();
        Map<String, Object> response =
                tokenMintPort.mintForRefreshGrant(existing, client, grantedScope, ipAddress, userAgent);

        // Rotate AFTER the tenant guard passed: revoke the presented token and
        // mint a successor in the same family, then inject its raw wire value.
        RefreshToken rotated = refreshTokenService.rotateRefreshToken(existing, ipAddress, userAgent);
        response.put("refresh_token", rotated.getToken());
        long refreshExpiresIn =
                Duration.between(Instant.now(), rotated.getExpiryDate()).getSeconds();
        response.put("refresh_expires_in", refreshExpiresIn);

        log.info("OAuth2 refresh_token grant — rotated token for client: {}", clientId);
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
     * <p>SECURITY_REVIEW_2026-05-01 §"Out-of-scope but worth flagging" #2:
     * reject ID tokens replayed against this endpoint. Per OIDC Core §5.3.1,
     * UserInfo MUST be called with an OAuth 2.0 access token, not an ID token.
     * The access tokens minted at {@link #exchangeCode} carry {@code type=oauth2};
     * ID tokens carry {@code type=id_token}. Without this check, any RS256-signed
     * token with a valid email subject was accepted, making the ID-token a
     * stand-in for the access token.</p>
     *
     * @return map of OIDC standard claims
     */
    public Map<String, Object> getUserInfo(String accessToken) {
        // #47 (2026-05-21): parse + signature-verify the access token exactly
        // once, then read every claim (type / subject / scope) from this single
        // Claims object. The previous code invoked jwtService three times, each
        // of which re-parsed and re-verified the same JWT.
        Claims tokenClaims = jwtService.parseAllClaims(accessToken);

        String type = tokenClaims.get("type", String.class);
        if (!"oauth2".equals(type)) {
            // RFC 6750 §3.1 — Bearer-token errors at a resource endpoint use
            // `invalid_token`, not `invalid_client` (which is only for the auth
            // server's token endpoint). Pass explicit errorCode so the default
            // status-to-code mapper does not stamp `invalid_client`.
            throw new OAuth2Exception(HttpStatus.UNAUTHORIZED,
                    "invalid_token",
                    "userinfo requires an OAuth2 access token");
        }
        String email = tokenClaims.getSubject();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // T-P1-SEC Fix C (2026-05-07): filter UserInfo claims by the access
        // token's authorised scopes (OIDC Core §5.4 — Requesting Claims using
        // Scope Values). Previously /userinfo returned email/name/phone
        // unconditionally regardless of which scopes the client was granted at
        // /token, contradicting the scope filter at exchangeCode():372-384.
        String scopeClaim = tokenClaims.get("scope", String.class);
        String scope = scopeClaim != null ? scopeClaim : "";

        Map<String, Object> claims = new LinkedHashMap<>();
        // Always include `sub` per OIDC Core §5.3. Phase 4: the userinfo subject
        // MUST equal the id_token subject (OIDC Core §5.3.2), so it is resolved
        // through the same PairwiseSubjectResolver, keyed on the relying party
        // stamped into the access token (`client_id`). With the flag off this is
        // the legacy user.id. If the access token predates this claim (in-flight
        // token minted before deploy) the client lookup is skipped and the
        // resolver still yields the legacy user.id when the flag is off; when the
        // flag is on a missing client falls back to the user id (stable, opaque).
        String tokenClientId = tokenClaims.get("client_id", String.class);
        OAuth2Client subjectClient = null;
        if (tokenClientId != null && !tokenClientId.isBlank()) {
            subjectClient = clientRepository.findByClientIdAndActiveTrue(tokenClientId).orElse(null);
        }
        claims.put("sub", pairwiseSubjectResolver.resolveSubject(user, subjectClient));

        if (scope.contains("email")) {
            claims.put("email", user.getEmail());
            claims.put("email_verified", user.isEmailVerified());
        }
        if (scope.contains("profile")) {
            claims.put("name", user.getFullName());
            claims.put("given_name", user.getFirstName());
            claims.put("family_name", user.getLastName());
            // `picture` and `locale` left out: not yet modelled on User entity.
            claims.put("updated_at",
                    user.getUpdatedAt() != null ? user.getUpdatedAt().getEpochSecond() : null);
        }
        if (scope.contains("phone") && user.getPhoneNumber() != null) {
            claims.put("phone_number", user.getPhoneNumber());
            claims.put("phone_number_verified", user.isPhoneVerified());
        }

        return claims;
    }

    /**
     * Returns true if {@code presentedSecret} matches the client's current
     * secret OR (during the post-rotation grace window) the previous
     * secret. Used by the /oauth2/token path so a freshly rotated
     * confidential client doesn't black-hole in-flight integrations.
     *
     * <p>See V58 migration + {@code OAuth2Client.rotateSecret(...)} +
     * {@code OAuth2Client.isPreviousSecretValid()}.</p>
     */
    private boolean matchesCurrentOrPreviousSecret(OAuth2Client client, String presentedSecret) {
        if (passwordEncoder.matches(presentedSecret, client.getClientSecret())) {
            return true;
        }
        if (client.isPreviousSecretValid()
                && passwordEncoder.matches(presentedSecret, client.getPreviousSecret())) {
            log.warn("OAuth2 client_secret matched the prior (rotation grace) secret: clientId={}",
                    client.getClientId());
            return true;
        }
        return false;
    }
}
