package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.OAuth2Service;
import com.fivucsas.identity.entity.OAuth2Client;
import io.swagger.v3.oas.annotations.Operation;
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
 * Provides endpoints for:
 * - Authorization initiation (authorize)
 * - Token exchange (token)
 * - User info retrieval (userinfo)
 *
 * Designed for the embeddable auth widget to authenticate users
 * via standard OAuth 2.0 / OpenID Connect flows.
 */
@RestController
@RequestMapping("/api/v1/oauth2")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth2", description = "OAuth 2.0 / OpenID Connect endpoints for embeddable auth widget")
public class OAuth2Controller {

    private final OAuth2Service oAuth2Service;

    /**
     * Initiates the OAuth 2.0 authorization code flow.
     * Validates the client and parameters, then returns session info
     * so the auth widget can proceed with authentication.
     *
     * For the embeddable widget flow, the user authenticates in the widget
     * and then the widget calls this endpoint to get an authorization code.
     */
    @GetMapping("/authorize")
    @Operation(summary = "Initiate OAuth 2.0 authorization code flow")
    public ResponseEntity<?> authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "response_type", defaultValue = "code") String responseType,
            @RequestParam(value = "scope", required = false, defaultValue = "openid profile email") String scope,
            @RequestParam(value = "state", required = false) String state,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        log.info("OAuth2 authorize request: client_id={}, response_type={}", clientId, responseType);

        // Validate response_type
        if (!"code".equals(responseType)) {
            return errorResponse(400, "unsupported_response_type",
                    "Only response_type=code is supported", state, httpRequest);
        }

        try {
            // Validate client and redirect URI
            OAuth2Client client = oAuth2Service.validateClient(clientId, redirectUri);

            // Validate scopes
            oAuth2Service.validateScopes(client, scope);

            // If user is authenticated, generate the code directly
            if (authentication != null && authentication.isAuthenticated()) {
                String code = oAuth2Service.generateAuthorizationCode(
                        authentication.getName(), clientId, redirectUri, scope);

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("code", code);
                response.put("state", state);
                response.put("redirect_uri", redirectUri);
                return ResponseEntity.ok(response);
            }

            // If not authenticated, return auth session info for the widget
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("action", "authenticate");
            response.put("client_id", clientId);
            response.put("client_name", client.getClientName());
            response.put("scope", scope);
            response.put("state", state);
            response.put("redirect_uri", redirectUri);
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.warn("OAuth2 authorize failed: {}", e.getMessage());
            return errorResponse(400, "invalid_request", e.getMessage(), state, httpRequest);
        }
    }

    /**
     * Exchanges an authorization code for access and ID tokens.
     * Standard OAuth 2.0 token endpoint.
     */
    @PostMapping("/token")
    @Operation(summary = "Exchange authorization code for tokens")
    public ResponseEntity<?> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam("code") String code,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "client_secret", required = false) String clientSecret,
            HttpServletRequest httpRequest) {

        log.info("OAuth2 token request: grant_type={}, client_id={}", grantType, clientId);

        if (!"authorization_code".equals(grantType)) {
            return errorResponse(400, "unsupported_grant_type",
                    "Only grant_type=authorization_code is supported", null, httpRequest);
        }

        try {
            Map<String, Object> tokens = oAuth2Service.exchangeCode(code, clientId, redirectUri, clientSecret);
            return ResponseEntity.ok(tokens);
        } catch (IllegalArgumentException e) {
            log.warn("OAuth2 token exchange failed: {}", e.getMessage());
            return errorResponse(400, "invalid_grant", e.getMessage(), null, httpRequest);
        }
    }

    /**
     * Returns authenticated user claims (OIDC UserInfo endpoint).
     * Requires a valid Bearer access token.
     */
    @GetMapping("/userinfo")
    @Operation(summary = "Get authenticated user info (OIDC UserInfo)",
               security = @SecurityRequirement(name = "bearer-jwt"))
    public ResponseEntity<?> userInfo(HttpServletRequest httpRequest) {
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "invalid_token", "error_description", "Bearer token required"));
        }

        String token = authHeader.substring(7);

        try {
            Map<String, Object> claims = oAuth2Service.getUserInfo(token);
            return ResponseEntity.ok(claims);
        } catch (Exception e) {
            log.warn("OAuth2 userinfo failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "invalid_token", "error_description", "Invalid or expired token"));
        }
    }

    /**
     * Build a standard OAuth 2.0 error response.
     */
    private ResponseEntity<Map<String, Object>> errorResponse(
            int status, String error, String description, String state, HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        if (state != null) {
            body.put("state", state);
        }
        return ResponseEntity.status(status).body(body);
    }
}
