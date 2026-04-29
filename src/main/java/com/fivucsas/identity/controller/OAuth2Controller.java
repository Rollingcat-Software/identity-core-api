package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.OAuth2ClientRepositoryPort;
import com.fivucsas.identity.application.service.OAuth2Service;
import com.fivucsas.identity.domain.exception.PkceVerificationException;
import com.fivucsas.identity.entity.MfaSession;
import com.fivucsas.identity.entity.OAuth2Client;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.repository.MfaSessionRepository;
import com.fivucsas.identity.security.RateLimitService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
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
import java.util.UUID;

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
    private final AuditLogPort auditLogPort;
    private final RateLimitService rateLimitService;

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
            @Parameter(description = "OIDC ui_locales — preferred UI language(s), space-separated BCP47 tags (e.g. 'tr' or 'en-US tr')")
            @RequestParam(value = "ui_locales", required = false) String uiLocales,
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

            // OIDC §3.1.2.1 content negotiation: redirect to the hosted login surface
            // only on explicit display=page. The SDK (FivucsasAuth.loginRedirect) always
            // sets this, so the Accept: text/html fallback branch was redundant and
            // could accidentally redirect XHR callers that happened to pass text/html.
            if ("page".equalsIgnoreCase(display)) {
                URI location = buildHostedLoginUri(clientId, redirectUri, scope, state, nonce,
                        codeChallenge, codeChallengeMethod, uiLocales);
                return ResponseEntity.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, location.toString())
                        .header(HttpHeaders.CACHE_CONTROL, "no-store")
                        .build();
            }

            // If user is authenticated, generate the code directly
            if (authentication != null && authentication.isAuthenticated()) {
                // Audit BE-H2 (2026-04-19): replicate the /authorize/complete
                // PKCE + tenant + confidential checks here. The GET branch was
                // previously minting codes with no PKCE enforcement for public
                // clients and no user↔client tenant guard.
                ResponseEntity<Map<String, Object>> validationError =
                        validateAuthorizeRequest(client, authentication.getName(),
                                codeChallenge, codeChallengeMethod, state);
                if (validationError != null) {
                    return validationError;
                }

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
    public ResponseEntity<?> authorizeComplete(@Valid @RequestBody HostedAuthorizeCompleteRequest body) {
        // Bean Validation (@NotBlank/@Pattern/@Size on the request DTO) enforces
        // structural correctness before this body runs. The local
        // MethodArgumentNotValidException handler returns the OAuth2 error shape
        // ({error, error_description, [state]}) so RFC 6749 §5.2 is preserved.
        // The body == null guard remains for defense-in-depth — Spring should
        // already reject empty bodies via HttpMessageNotReadableException.
        if (body == null) {
            return errorResponse(400, "invalid_request",
                    "Request body is required", null);
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

        // Cross-client replay defense: when the MFA session was created with a
        // bound client_id (hosted-login flow), require the code mint to use the
        // same client_id. Null binding is allowed — it represents widget step-up
        // MFA, which is client-agnostic by design.
        if (session.getClientId() != null && !session.getClientId().equals(body.clientId)) {
            log.warn("OAuth2 authorize/complete — client_id mismatch: session={}, request={}",
                    session.getClientId(), body.clientId);
            return errorResponse(400, "invalid_request",
                    "MFA session is bound to a different client_id", body.state);
        }

        OAuth2Client client;
        try {
            client = oAuth2Service.validateClient(body.clientId, body.redirectUri);
            oAuth2Service.validateScopes(client, body.scope);
        } catch (IllegalArgumentException e) {
            log.warn("OAuth2 authorize/complete failed: {}", e.getMessage());
            return errorResponse(400, "invalid_request", e.getMessage(), body.state);
        }

        // Shared PKCE + tenant + confidential-secret checks. See
        // validateAuthorizeRequest() below — also used by the GET branch.
        ResponseEntity<Map<String, Object>> validationError = validateAuthorizeRequest(
                client, session.getUserId(), body.codeChallenge, body.codeChallengeMethod, body.state);
        if (validationError != null) {
            return validationError;
        }

        User user = userRepository.findById(session.getUserId()).orElse(null);
        if (user == null) {
            return errorResponse(400, "invalid_request", "User not found for MFA session", body.state);
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

    /**
     * Shared validation for both {@code GET /authorize} (authenticated branch) and
     * {@code POST /authorize/complete}. Enforces:
     * <ul>
     *   <li>PKCE S256 mandatory for public clients (RFC 7636 + RFC 8252 §8.1).</li>
     *   <li>{@code code_challenge_method=plain} rejected — only S256 is accepted.</li>
     *   <li>User tenant must equal client tenant (multi-tenant isolation).</li>
     * </ul>
     * Returns {@code null} on success, or the error {@code ResponseEntity} the caller
     * should return unchanged.
     *
     * @param client validated OAuth2 client (tenant non-null)
     * @param userKey either a {@code UUID} (user id) or a {@code String} (email) used
     *                to resolve the user for the tenant check
     * @param codeChallenge PKCE challenge (nullable)
     * @param codeChallengeMethod PKCE method (nullable; defaults to S256)
     * @param state OAuth2 state (echoed in any error body)
     */
    private ResponseEntity<Map<String, Object>> validateAuthorizeRequest(
            OAuth2Client client,
            Object userKey,
            String codeChallenge,
            String codeChallengeMethod,
            String state) {

        // PKCE enforcement for public clients (RFC 7636 + RFC 8252 §8.1).
        // Public clients cannot hold a client_secret, so PKCE S256 is the only
        // protection against code interception. Plain is rejected — only S256
        // provides the hash that makes the verifier safe to transmit.
        if (!client.isConfidential()) {
            if (isBlank(codeChallenge)) {
                return errorResponse(400, "invalid_request",
                        "code_challenge is required for public clients (PKCE S256 mandatory)", state);
            }
            String method = codeChallengeMethod == null ? "S256" : codeChallengeMethod;
            if (!"S256".equalsIgnoreCase(method)) {
                return errorResponse(400, "invalid_request",
                        "code_challenge_method must be S256 for public clients; plain is not allowed", state);
            }
        }

        // Resolve user (by id or email) for the tenant check. Null/missing user
        // is reported generically to avoid leaking enumeration signal.
        User user = null;
        if (userKey instanceof UUID uid) {
            user = userRepository.findById(uid).orElse(null);
        } else if (userKey instanceof String email && !email.isBlank()) {
            user = userRepository.findByEmail(email).orElse(null);
        }
        if (user == null) {
            return errorResponse(400, "invalid_request", "User not found", state);
        }

        // Tenant isolation: a code must never be minted for a client that belongs
        // to a different tenant than the authenticated user. RFC 6749 §5.2 maps
        // this to 400 invalid_request (not 403) to avoid leaking policy info.
        if (user.getTenant() == null || client.getTenant() == null
                || !user.getTenant().getId().equals(client.getTenant().getId())) {
            log.warn("OAuth2 authorize — tenant mismatch: userTenant={}, clientTenant={}",
                    user.getTenant() == null ? null : user.getTenant().getId(),
                    client.getTenant() == null ? null : client.getTenant().getId());
            return errorResponse(400, "invalid_request",
                    "Client does not belong to user's tenant", state);
        }

        return null;
    }

    private URI buildHostedLoginUri(String clientId, String redirectUri, String scope, String state,
                                    String nonce, String codeChallenge, String codeChallengeMethod,
                                    String uiLocales) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(hostedLoginUrl)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code");
        if (scope != null) builder.queryParam("scope", scope);
        if (state != null) builder.queryParam("state", state);
        if (nonce != null) builder.queryParam("nonce", nonce);
        if (codeChallenge != null) builder.queryParam("code_challenge", codeChallenge);
        if (codeChallengeMethod != null) builder.queryParam("code_challenge_method", codeChallengeMethod);
        // OIDC Core §3.1.2.1: forward ui_locales so the hosted login page renders
        // in the tenant's requested language. The hosted page supports 'en' and
        // 'tr'; other tags are ignored in favor of browser auto-detect fallback.
        if (uiLocales != null && !uiLocales.isBlank()) {
            builder.queryParam("ui_locales", uiLocales);
        }
        return builder.build().toUri();
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * Resolve the request's actor IP, honoring an upstream X-Forwarded-For
     * proxy header (Traefik in prod). Mirrors the helper in
     * {@code RateLimitInterceptor} — kept local to avoid widening the
     * interceptor's API surface for an unrelated callsite.
     */
    private String getClientIP(HttpServletRequest request) {
        if (request == null) return null;
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isBlank()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }

    /**
     * Request body for POST /oauth2/authorize/complete.
     *
     * <p>Bean Validation constraints (Sec-P2 #7, 2026-04-29) enforce structural
     * correctness so the controller body can focus on protocol semantics. On
     * violation, the controller-scoped {@link #handleValidationOnAuthorizeComplete}
     * adapter rewrites the standard Spring 400 into the OAuth 2.0 error shape
     * (RFC 6749 §5.2) — {@code {error, error_description, state?}}.
     */
    public static class HostedAuthorizeCompleteRequest {
        @NotBlank(message = "mfaSessionToken is required")
        @Size(max = 256, message = "mfaSessionToken too long")
        public String mfaSessionToken;

        @NotBlank(message = "clientId is required")
        @Size(max = 128, message = "clientId too long")
        public String clientId;

        @NotBlank(message = "redirectUri is required")
        @Pattern(
            regexp = "^https?://[\\w.-]+(:\\d+)?(/[\\w./?%&=#:+~,@!$'()*;\\[\\]-]*)?$",
            message = "redirectUri must be a valid http(s) URL"
        )
        @Size(max = 2048, message = "redirectUri too long")
        public String redirectUri;

        @Size(max = 512, message = "scope too long")
        public String scope;

        @Size(max = 512, message = "state too long")
        public String state;

        @Size(max = 512, message = "nonce too long")
        public String nonce;

        @Size(max = 256, message = "codeChallenge too long")
        public String codeChallenge;

        @Size(max = 16, message = "codeChallengeMethod too long")
        public String codeChallengeMethod;
    }

    /**
     * Local override of the global {@link MethodArgumentNotValidException}
     * handler. The OAuth 2.0 error shape (RFC 6749 §5.2) requires
     * {@code {error, error_description, [state]}} — not the generic
     * {@link com.fivucsas.identity.dto.ErrorResponse} envelope used by the
     * rest of the API. We extract the first field error's message as the
     * {@code error_description} and echo {@code state} when present.
     *
     * <p>Sec-P2 #7, 2026-04-29.
     */
    @ExceptionHandler(org.springframework.web.bind.MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationOnAuthorizeComplete(
            org.springframework.web.bind.MethodArgumentNotValidException ex,
            HttpServletRequest request) {
        String description = ex.getBindingResult().getFieldErrors().stream()
                .map(org.springframework.validation.FieldError::getDefaultMessage)
                .findFirst()
                .orElse("Invalid request");
        String state = null;
        Object target = ex.getBindingResult().getTarget();
        if (target instanceof HostedAuthorizeCompleteRequest req) {
            state = req.state;
        }
        log.warn("OAuth2 authorize/complete — request body validation failed: {}", description);
        return errorResponse(400, "invalid_request", description, state);
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
        } catch (PkceVerificationException e) {
            // Phase D5a + D5b: audit-log every PKCE/code failure with clientId +
            // actorIp + reason, then bump the per-clientId failure bucket. If the
            // bucket is now empty, return 429 with Retry-After instead of the
            // standard invalid_grant body — but ONLY after we've audited the
            // attempt, so SOC sees the full attack pattern.
            String actorIp = getClientIP(httpRequest);
            auditLogPort.logPkceFailure(e.getClientId(), actorIp, e.getReason().name());

            boolean withinBudget = rateLimitService.recordAndAllowPkceFailure(e.getClientId());
            if (!withinBudget) {
                long retryAfter = rateLimitService.getSecondsUntilRefill(
                        e.getClientId(), RateLimitService.RateLimitType.PKCE_FAILURE);
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("error", "invalid_grant");
                body.put("error_description",
                        "Too many PKCE failures for this client. Please slow down.");
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                        .header("Retry-After", String.valueOf(retryAfter))
                        .body(body);
            }

            log.warn("OAuth2 PKCE failure: clientId={}, reason={}, ip={}",
                    e.getClientId(), e.getReason(), actorIp);
            // RFC 6749 §5.2: PKCE failures map to invalid_grant — wire format
            // unchanged from previous build, so existing clients see the same
            // response shape.
            return errorResponse(400, "invalid_grant", e.getMessage(), null);
        } catch (com.fivucsas.identity.domain.exception.OAuth2Exception e) {
            // BE-M2 (2026-04-19): explicit status (e.g. 401 for missing
            // confidential-client secret) rather than blanket 400.
            log.warn("OAuth2 token exchange rejected: {} {}", e.getStatus(), e.getMessage());
            return errorResponse(e.getStatus().value(), e.getErrorCode(), e.getMessage(), null);
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
