package com.fivucsas.identity.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

/**
 * OpenID Connect discovery and JWKS endpoints.
 *
 * Provides:
 * - /.well-known/openid-configuration — OIDC discovery document (required by OIDC Discovery 1.0)
 * - /.well-known/jwks.json — JSON Web Key Set metadata (RFC 7517)
 *
 * These endpoints allow relying parties (auth widget, third-party apps)
 * to discover the identity provider's capabilities.
 */
@RestController
@Slf4j
@Tag(name = "OpenID Connect", description = "OIDC discovery and key endpoints")
public class OpenIDConfigController {

    @Value("${app.base-url:https://api.fivucsas.com}")
    private String baseUrl;

    /**
     * OIDC Discovery document (OpenID Connect Discovery 1.0 Section 4).
     * Returns metadata about the identity provider's configuration.
     * All required fields per spec are included.
     */
    @GetMapping("/.well-known/openid-configuration")
    @Operation(summary = "OpenID Connect discovery document")
    public ResponseEntity<Map<String, Object>> openidConfiguration() {
        Map<String, Object> config = new LinkedHashMap<>();

        // Required fields (OpenID Connect Discovery 1.0 Section 3)
        config.put("issuer", baseUrl);
        config.put("authorization_endpoint", baseUrl + "/api/v1/oauth2/authorize");
        config.put("token_endpoint", baseUrl + "/api/v1/oauth2/token");
        config.put("userinfo_endpoint", baseUrl + "/api/v1/oauth2/userinfo");
        config.put("jwks_uri", baseUrl + "/.well-known/jwks.json");

        config.put("response_types_supported", List.of("code"));
        config.put("response_modes_supported", List.of("query"));
        config.put("grant_types_supported", List.of("authorization_code"));
        config.put("subject_types_supported", List.of("public"));
        // JwtService uses Jwts.SIG.HS512 — must match actual signing algorithm
        config.put("id_token_signing_alg_values_supported", List.of("HS512"));
        config.put("scopes_supported", List.of("openid", "profile", "email", "phone"));
        config.put("token_endpoint_auth_methods_supported", List.of("client_secret_post", "none"));
        config.put("claims_supported", List.of(
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "email", "email_verified",
                "name", "given_name", "family_name",
                "phone_number", "phone_number_verified",
                "updated_at"
        ));

        // PKCE support (RFC 7636)
        config.put("code_challenge_methods_supported", List.of("S256", "plain"));

        // Service documentation
        config.put("service_documentation", "https://app.fivucsas.com/developer-portal");

        return ResponseEntity.ok(config);
    }

    /**
     * JSON Web Key Set endpoint (RFC 7517).
     *
     * Since this service uses HMAC-SHA512 (symmetric key), the JWKS
     * exposes key metadata only — the actual secret is never exposed.
     * For HMAC-signed tokens, relying parties should validate tokens
     * via the UserInfo endpoint or token introspection, not via JWKS.
     *
     * Note: symmetric keys (kty=oct) in JWKS cannot be used by external
     * parties for verification. This endpoint exists for discovery
     * compliance; use /api/v1/oauth2/userinfo for token validation.
     */
    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "JSON Web Key Set for token verification metadata")
    public ResponseEntity<Map<String, Object>> jwks() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "oct");
        jwk.put("use", "sig");
        jwk.put("alg", "HS512");
        jwk.put("kid", "fivucsas-identity-key-1");
        jwk.put("key_ops", List.of("sign", "verify"));

        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", List.of(jwk));

        return ResponseEntity.ok(jwks);
    }

}
