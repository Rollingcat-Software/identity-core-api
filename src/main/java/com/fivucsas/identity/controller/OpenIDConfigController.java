package com.fivucsas.identity.controller;

import com.fivucsas.identity.security.JwtSecretProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.*;

/**
 * OpenID Connect discovery and JWKS endpoints.
 *
 * Provides:
 * - /.well-known/openid-configuration — OIDC discovery document
 * - /.well-known/jwks.json — JSON Web Key Set for token verification
 *
 * These endpoints allow relying parties (auth widget, third-party apps)
 * to discover the identity provider's capabilities and verify tokens.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OpenID Connect", description = "OIDC discovery and key endpoints")
public class OpenIDConfigController {

    private final JwtSecretProvider jwtSecretProvider;

    @Value("${app.base-url:https://auth.rollingcatsoftware.com}")
    private String baseUrl;

    /**
     * OIDC Discovery document.
     * Returns metadata about the identity provider's configuration.
     */
    @GetMapping("/.well-known/openid-configuration")
    @Operation(summary = "OpenID Connect discovery document")
    public ResponseEntity<Map<String, Object>> openidConfiguration() {
        Map<String, Object> config = new LinkedHashMap<>();

        config.put("issuer", baseUrl);
        config.put("authorization_endpoint", baseUrl + "/api/v1/oauth2/authorize");
        config.put("token_endpoint", baseUrl + "/api/v1/oauth2/token");
        config.put("userinfo_endpoint", baseUrl + "/api/v1/oauth2/userinfo");
        config.put("jwks_uri", baseUrl + "/.well-known/jwks.json");

        config.put("response_types_supported", List.of("code"));
        config.put("grant_types_supported", List.of("authorization_code"));
        config.put("subject_types_supported", List.of("public"));
        config.put("id_token_signing_alg_values_supported", List.of("HS256"));
        config.put("scopes_supported", List.of("openid", "profile", "email", "phone"));
        config.put("token_endpoint_auth_methods_supported", List.of("client_secret_post"));
        config.put("claims_supported", List.of(
                "sub", "iss", "aud", "exp", "iat",
                "email", "email_verified",
                "name", "given_name", "family_name",
                "phone_number", "phone_number_verified",
                "updated_at"
        ));

        return ResponseEntity.ok(config);
    }

    /**
     * JSON Web Key Set endpoint.
     * Returns the public key(s) used to verify token signatures.
     *
     * Since this service uses HMAC-SHA256 (symmetric key), the JWKS
     * exposes key metadata without the actual secret value.
     * Token verification should be done server-side via the token
     * introspection or userinfo endpoint.
     */
    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "JSON Web Key Set for token verification")
    public ResponseEntity<Map<String, Object>> jwks() {
        // For HMAC-SHA256, we expose key metadata (not the secret itself)
        // Clients should use the userinfo endpoint for token validation
        SecretKey key = getSignInKey();

        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "oct");
        jwk.put("use", "sig");
        jwk.put("alg", "HS256");
        jwk.put("kid", "fivucsas-identity-key-1");
        // Key length in bits (do NOT expose the actual key value)
        jwk.put("key_ops", List.of("verify"));

        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", List.of(jwk));

        return ResponseEntity.ok(jwks);
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecretProvider.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
