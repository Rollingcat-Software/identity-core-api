package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.application.service.OAuth2Service;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.repository.MfaSessionRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST controller for OAuth 2.0 authorization code flow.
 *
 * RFC compliance:
 * - RFC 6749 (OAuth 2.0): authorization endpoint, token endpoint, error responses
 * - RFC 7636 (PKCE): code_challenge, code_challenge_method, code_verifier
 * - OpenID Connect Core 1.0: nonce, userinfo endpoint, ID token claims
 *
 * Provides endpoints for:
 * - Authorization initiation (GET /authorize)
 * - Token exchange (POST /token)
 * - User info retrieval (GET /userinfo)
 */
@RestController
@RequestMapping("/api/v1/oauth2")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth2", description = "OAuth 2.0 / OpenID Connect endpoints")
public class OAuth2Controller {

    private final OAuth2Service oAuth2Service;
    private final OAuth2ClientRepositoryPort clientRepository;
    private final MfaSessionRepository mfaSessionRepository;
    private final UserRepository userRepository;

    @Value("${app.hosted-login-url:https://verify.fivucsas.com/login}")
    private String hostedLoginUrl;

    /**
     * OAuth 2.0 Authorization Endpoint (RFC 6749 Section 3.1).
     *
     * Validates the client and parameters, then either:
     * - Returns an authorization code if user is already authenticated
     * - Returns session info for the widget to initiate authentication
     *
     * Supports PKCE (RFC 7636) via code_challenge and code_challenge_method.
     * Supports OIDC nonce parameter.
     */
    @GetMapping("/authorize")
    @Operation(summary = "Initiate OAuth 2.0 authorization code flow")
    public ResponseEntity<?> authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "response_type", defaultValue = "code") String responseType,
            @RequestParam(value = "scope", required = false, defaultValue = "openid profile email") String scope,
            @Parameter(description = "CSRF protection state parameter (RECOMMENDED, returned unchanged)")
            @RequestParam(value = "state", required = false) String state,
            @Parameter(description = "OIDC nonce for ID token replay protection")
            @RequestParam(value = "nonce", required = false) String nonce,
            @Parameter(description = "PKCE code challenge (RFC 7636)")
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @Parameter(description = "PKCE code challenge method: S256 (recommended) or plain")
            @RequestParam(value = "code_challenge_method", required = false, defaultValue = "S256") String codeChallengeMethod,
            @Parameter(description = "OIDC display hint — set to 'page' for a hosted redirective login, otherwise the JSON widget flow runs")
            @RequestParam(value = "display", required = false) String display,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        log.info("OAuth2 authorize request: client_id={}, response_type={}, display={}", clientId, responseType, display);

        // RFC 6749 Section 3.1.1: response_type is REQUIRED
        if (!"code".equals(responseType)) {
            return errorResponse(400, "unsupported_response_type",
                    "Only response_type=code is supported", state);
        }

        // Validate code_challenge_method if code_challenge is present
        if (codeChallenge != null && !codeChallenge.isEmpty()) {
            if (!"S256".equalsIgnoreCase(codeChallengeMethod) && !"plain".equalsIgnoreCase(codeChallengeMethod)) {
                return errorResponse(400, "invalid_request",
                        "code_challenge_method must be S256 or plain", state);
            }
        }

        try {
            // Validate client and redirect URI (exact match per RFC 6749 Section 3.1.2.3)
            OAuth2Client client = oAuth2Service.validateClient(clientId, redirectUri);

            // Validate scopes
            oAuth2Service.validateScopes(client, scope);

            // OIDC §3.1.2.1 content negotiation: display=page, or browsers asking for HTML,
            // get a 302 to the hosted login surface. The JSON response below stays the
            // contract for the inline widget flow, so existing tenants don't break.
            boolean wantsHtml = isHtmlAccept(httpRequest.getHeader(HttpHeaders.ACCEPT));
            if ("page".equalsIgnoreCase(display) || wantsHtml) {
                URI location = buildHostedLoginUri(clientId, redirectUri, scope, state, nonce,
                        codeChallenge, codeChallengeMethod);
                return ResponseEntity.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, location.toString())
                        .header(HttpHeaders.CACHE_CONTROL, "no-store")
                        .build();
            }

            // If user is authenticated, generate the code directly
            if (authentication != null && authentication.isAuthenticated()) {
                String code = oAuth2Service.generateAuthorizationCode(
                        authentication.getName(), clientId, redirectUri, scope,
                        nonce, codeChallenge, codeChallengeMethod);

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("code", code);
                // RFC 6749 Section 4.1.2: state MUST be returned if provided
                if (state != null) {
                    response.put("state", state);
                }
                response.put("redirect_uri", redirectUri);
                return ResponseEntity.ok(response);
            }

            // If not authenticated, return auth session info for the widget
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("action", "authenticate");
            response.put("client_id", clientId);
            response.put("client_name", client.getClientName());
            response.put("scope", scope);
            if (state != null) {
                response.put("state", state);
            }
            response.put("redirect_uri", redirectUri);
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.warn("OAuth2 authorize failed: {}", e.getMessage());
            // RFC 6749 Section 4.1.2.1: authorization-endpoint error responses.
            // Unknown/invalid client_id and redirect_uri are parameter-validation
            // failures — RFC-correct code is invalid_request, not unauthorized_client
            // (which signals grant-type mismatch for an otherwise-valid client).
            return errorResponse(400, "invalid_request", e.getMessage(), state);
        }
    }

    /**
     * POST /oauth2/authorize/complete
     *
     * Called by the hosted login page ({@code verify.fivucsas.com/login}) after MFA
     * has finished. Trades an already-completed MfaSession for a single-use OAuth 2.0
     * authorization code, which the browser then posts to the tenant's redirect URI.
     * <p>
     * Security:
     * <ul>
     *   <li>MfaSession must be marked completed and not expired.</li>
     *   <li>clientId + redirectUri are re-validated against the allowlist — URL params
     *       are never trusted.</li>
     *   <li>The MfaSession is deleted immediately after code minting (single-use).</li>
     * </ul>
     */
    @PostMapping("/authorize/complete")
    @Operation(summary = "Mint an OAuth2 authorization code after hosted-login MFA completes")
    @Transactional
    public ResponseEntity<?> authorizeComplete(@RequestBody HostedAuthorizeCompleteRequest body) {
        if (body == null || isBlank(body.mfaSessionToken) || isBlank(body.clientId) || isBlank(body.redirectUri)) {
            return errorResponse(400, "invalid_request",
                    "mfaSessionToken, clientId, and redirectUri are required", body == null ? null : body.state);
        }

        MfaSession session = mfaSessionRepository.findBySessionToken(body.mfaSessionToken).orElse(null);
        if (session == null) {
            return errorResponse(400, "invalid_request", "Unknown MFA session", body.state);
        }
        if (session.isExpired()) {
            return errorResponse(400, "invalid_request", "MFA session expired", body.state);
        }
        if (!session.isCompleted()) {
            return errorResponse(400, "invalid_request", "MFA not completed", body.state);
        }
        // Anti-replay: reject any session already spent by a prior code mint. The
        // consumed_at flip below happens inside the same @Transactional boundary as
        // the code generation, so failures after flip roll both back atomically.
        if (session.isConsumed()) {
            log.warn("OAuth2 authorize/complete — attempt to reuse consumed MFA session: token={}",
                    body.mfaSessionToken);
            return errorResponse(400, "invalid_request", "MFA session already used", body.state);
        }

        OAuth2Client client;
        try {
            client = oAuth2Service.validateClient(body.clientId, body.redirectUri);
            oAuth2Service.validateScopes(client, body.scope);
        } catch (IllegalArgumentException e) {
            log.warn("OAuth2 authorize/complete failed: {}", e.getMessage());
            return errorResponse(400, "invalid_request", e.getMessage(), body.state);
        }

        // PKCE enforcement for public clients (RFC 7636 + RFC 8252 §8.1).
        // Public clients cannot hold a client_secret, so PKCE S256 is the only
        // protection against code interception. Plain is rejected — only S256
        // provides the hash that makes the verifier safe to transmit.
        if (!client.isConfidential()) {
            if (isBlank(body.codeChallenge)) {
                return errorResponse(400, "invalid_request",
                        "code_challenge is required for public clients (PKCE S256 mandatory)", body.state);
            }
            if (!"S256".equalsIgnoreCase(body.codeChallengeMethod)) {
                return errorResponse(400, "invalid_request",
                        "code_challenge_method must be S256 for public clients; plain is not allowed", body.state);
            }
        }

        User user = userRepository.findById(session.getUserId()).orElse(null);
        if (user == null) {
            return errorResponse(400, "invalid_request", "User not found for MFA session", body.state);
        }
        if (!user.getTenant().getId().equals(client.getTenant().getId())) {
            // Prevents a code mint against a client that belongs to a different tenant than the authenticated user
            return errorResponse(403, "access_denied", "Client does not belong to user's tenant", body.state);
        }

        // Mark consumed BEFORE minting the code so a crash between consume and mint
        // leaves the session poisoned (still marked consumed) and the transaction
        // rolls back the consume with the mint.
        session.consume();
        mfaSessionRepository.save(session);

        String code = oAuth2Service.generateAuthorizationCode(
                user.getEmail(), body.clientId, body.redirectUri,
                body.scope == null ? "openid profile email" : body.scope,
                body.nonce, body.codeChallenge, body.codeChallengeMethod);

        // Burn the MFA session record so it can't be replayed for a second code.
        // Runs inside the same @Transactional — delete + consume + code mint all
        // commit or rollback together.
        mfaSessionRepository.delete(session);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("code", code);
        response.put("redirect_uri", body.redirectUri);
        if (body.state != null) {
            response.put("state", body.state);
        }
        log.info("OAuth2 hosted code minted — userId={}, clientId={}", user.getId(), body.clientId);
        return ResponseEntity.ok(response);
    }

    /**
     * GET /oauth2/clients/{clientId}/public
     *
     * Returns the publicly displayable metadata the hosted login page needs to render
     * branding ("You're signing in to ACME"). No auth required — rate-limited upstream.
     */
    @GetMapping("/clients/{clientId}/public")
    @Operation(summary = "Public client metadata for hosted-login branding")
    public ResponseEntity<?> getClientPublicMeta(@PathVariable("clientId") String clientId) {
        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId).orElse(null);
        if (client == null || !client.isValid()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "not_found", "error_description", "Unknown client_id"));
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("client_id", client.getClientId());
        response.put("client_name", client.getClientName());
        response.put("tenant_name", client.getTenant() != null ? client.getTenant().getName() : null);
        return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, "public, max-age=60").body(response);
    }

    private boolean isHtmlAccept(String accept) {
        return accept != null && accept.toLowerCase().contains("text/html");
    }

    private URI buildHostedLoginUri(String clientId, String redirectUri, String scope, String state,
                                    String nonce, String codeChallenge, String codeChallengeMethod) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(hostedLoginUrl)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code");
        if (scope != null) builder.queryParam("scope", scope);
        if (state != null) builder.queryParam("state", state);
        if (nonce != null) builder.queryParam("nonce", nonce);
        if (codeChallenge != null) builder.queryParam("code_challenge", codeChallenge);
        if (codeChallengeMethod != null) builder.queryParam("code_challenge_method", codeChallengeMethod);
        return builder.build().toUri();
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** Request body for POST /oauth2/authorize/complete. */
    public static class HostedAuthorizeCompleteRequest {
        public String mfaSessionToken;
        public String clientId;
        public String redirectUri;
        public String scope;
        public String state;
        public String nonce;
        public String codeChallenge;
        public String codeChallengeMethod;
    }

    /**
     * OAuth 2.0 Token Endpoint (RFC 6749 Section 3.2).
     *
     * Exchanges an authorization code for access and ID tokens.
     * Supports PKCE code_verifier validation (RFC 7636).
     * Client authentication via client_secret_post (RFC 6749 Section 2.3.1).
     */
    @PostMapping("/token")
    @Operation(summary = "Exchange authorization code for tokens")
    public ResponseEntity<?> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam("code") String code,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            @Parameter(description = "PKCE code verifier (RFC 7636)")
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            HttpServletRequest httpRequest) {

        log.info("OAuth2 token request: grant_type={}, client_id={}", grantType, clientId);

        if (!"authorization_code".equals(grantType)) {
            return errorResponse(400, "unsupported_grant_type",
                    "Only grant_type=authorization_code is supported", null);
        }

        try {
            Map<String, Object> tokens = oAuth2Service.exchangeCode(
                    code, clientId, redirectUri, clientSecret, codeVerifier);
            // RFC 6749 Section 5.1: must include Cache-Control: no-store
            return ResponseEntity.ok()
                    .header("Cache-Control", "no-store")
                    .header("Pragma", "no-cache")
                    .body(tokens);
        } catch (IllegalArgumentException e) {
            log.warn("OAuth2 token exchange failed: {}", e.getMessage());
            // RFC 6749 Section 5.2: use appropriate error codes
            String errorCode = "invalid_grant";
            if (e.getMessage().contains("client_secret")) {
                errorCode = "invalid_client";
            } else if (e.getMessage().contains("PKCE") || e.getMessage().contains("code_verifier")) {
                errorCode = "invalid_grant";
            }
            return errorResponse(400, errorCode, e.getMessage(), null);
        }
    }

    /**
     * OIDC UserInfo Endpoint (OpenID Connect Core Section 5.3).
     * Returns authenticated user claims. Requires a valid Bearer access token.
     */
    @GetMapping("/userinfo")
    @Operation(summary = "Get authenticated user info (OIDC UserInfo)",
               security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<?> userInfo(HttpServletRequest httpRequest) {
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // RFC 6750 Section 3: invalid_token error with WWW-Authenticate header
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header("WWW-Authenticate", "Bearer realm=\"fivucsas\", error=\"invalid_token\", error_description=\"Bearer token required\"")
                    .body(Map.of("error", "invalid_token", "error_description", "Bearer token required"));
        }

        String token = authHeader.substring(7);

        try {
            Map<String, Object> claims = oAuth2Service.getUserInfo(token);
            return ResponseEntity.ok(claims);
        } catch (Exception e) {
            log.warn("OAuth2 userinfo failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header("WWW-Authenticate", "Bearer realm=\"fivucsas\", error=\"invalid_token\", error_description=\"Invalid or expired token\"")
                    .body(Map.of("error", "invalid_token", "error_description", "Invalid or expired token"));
        }
    }

    /**
     * Build a standard OAuth 2.0 error response (RFC 6749 Section 5.2).
     */
    private ResponseEntity<Map<String, Object>> errorResponse(
            int status, String error, String description, String state) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        if (state != null) {
            body.put("state", state);
        }
        return ResponseEntity.status(status).body(body);
    }
}
