package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.OAuth2Service;
import com.fivucsas.identity.entity.OAuth2Client;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

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
            Authentication authentication,
            HttpServletRequest httpRequest) {

        log.info("OAuth2 authorize request: client_id={}, response_type={}", clientId, responseType);

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
            // RFC 6749 Section 4.1.2.1: error responses for authorization endpoint
            String errorCode = e.getMessage().contains("client_id") ? "unauthorized_client" : "invalid_request";
            return errorResponse(400, errorCode, e.getMessage(), state);
        }
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
