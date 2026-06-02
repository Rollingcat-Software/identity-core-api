package com.fivucsas.identity.controller;

import com.fivucsas.identity.security.RsaKeyProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
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

    // Phase 4 (flag-gated, default OFF). When true the OIDC `sub` is a pairwise
    // pseudonym per relying party, so the discovery doc advertises "pairwise"
    // instead of "public". Mirrors app.identity.oidc-subject-identity consumed by
    // PairwiseSubjectResolver — keep the two in lockstep.
    @Value("${app.identity.oidc-subject-identity:false}")
    private boolean pairwiseSubjectEnabled;

    private final RsaKeyProvider rsaKeyProvider;

    public OpenIDConfigController(RsaKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

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
        // Phase 4: advertise the active subject type. Default OFF → "public"
        // (sub = users.id, today's behaviour). Flag ON → "pairwise" (sub is an
        // identity-derived per-RP pseudonym, OIDC Core §8).
        config.put("subject_types_supported",
                List.of(pairwiseSubjectEnabled ? "pairwise" : "public"));
        // id_tokens are RS256-signed (fivucsas.jwt.default-algo=RS256) and verified by
        // relying parties via JWKS — which can only carry asymmetric keys. A symmetric
        // alg (HS512) can never appear in JWKS, so an RP cannot verify an HS512 id_token;
        // advertising it was misleading (doubly so now that allow-hs512=false). RS256 only.
        config.put("id_token_signing_alg_values_supported", List.of("RS256"));
        config.put("scopes_supported", List.of("openid", "profile", "email", "phone"));
        config.put("token_endpoint_auth_methods_supported", List.of("client_secret_post", "none"));
        config.put("claims_supported", List.of(
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "email", "email_verified",
                "name", "given_name", "family_name",
                "phone_number", "phone_number_verified",
                "updated_at"
        ));

        // PKCE support (RFC 7636). Only S256 is accepted — validateAuthorizeRequest
        // rejects code_challenge_method=plain for public clients, so advertising
        // "plain" was a metadata/enforcement mismatch. Advertise S256 only.
        config.put("code_challenge_methods_supported", List.of("S256"));

        // Service documentation
        config.put("service_documentation", "https://app.fivucsas.com/developer-portal");

        return ResponseEntity.ok(config);
    }

    /**
     * JSON Web Key Set endpoint (RFC 7517).
     *
     * Publishes the RS256 public key so relying parties (widget, third-party apps)
     * can verify ID tokens offline. The HS512 symmetric secret is intentionally
     * NOT published — by definition it cannot be shared without breaking security.
     * Legacy HS512 tokens remain accepted during the coexistence window and should
     * be validated via /userinfo or introspection.
     */
    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "JSON Web Key Set (RSA public key) for token verification")
    public ResponseEntity<Map<String, Object>> jwks() {
        RSAPublicKey pub = rsaKeyProvider.getPublicKey();

        Map<String, Object> rsaJwk = new LinkedHashMap<>();
        rsaJwk.put("kty", "RSA");
        rsaJwk.put("use", "sig");
        rsaJwk.put("alg", "RS256");
        rsaJwk.put("kid", rsaKeyProvider.getKid());
        rsaJwk.put("n", base64Url(pub.getModulus().toByteArray()));
        rsaJwk.put("e", base64Url(pub.getPublicExponent().toByteArray()));

        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", List.of(rsaJwk));

        return ResponseEntity.ok(jwks);
    }

    /**
     * Encodes a big-endian unsigned integer as base64url without padding per
     * RFC 7518 Section 6.3.1. Strips a leading sign byte if present.
     */
    private static String base64Url(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
