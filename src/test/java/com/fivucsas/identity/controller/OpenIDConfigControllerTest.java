package com.fivucsas.identity.controller;

import com.fivucsas.identity.security.RsaKeyProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BE-H1 — discovery + JWKS expose dual-algo metadata.
 */
@DisplayName("OpenID discovery + JWKS (BE-H1)")
class OpenIDConfigControllerTest {

    private OpenIDConfigController controller;

    @BeforeEach
    void setUp() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("test");
        RsaKeyProvider rsa = new RsaKeyProvider(env);
        ReflectionTestUtils.setField(rsa, "kid", RsaKeyProvider.DEFAULT_KID);
        rsa.initialize();
        controller = new OpenIDConfigController(rsa);
        ReflectionTestUtils.setField(controller, "baseUrl", "https://api.test.fivucsas.com");
    }

    @Test
    @DisplayName("/.well-known/openid-configuration advertises RS256 AND HS512")
    @SuppressWarnings("unchecked")
    void discoveryAdvertisesBothAlgs() {
        ResponseEntity<Map<String, Object>> resp = controller.openidConfiguration();
        assertThat(resp.getBody()).isNotNull();
        Object algs = resp.getBody().get("id_token_signing_alg_values_supported");
        assertThat(algs).isInstanceOf(List.class);
        List<String> algList = (List<String>) algs;
        assertThat(algList).contains("RS256", "HS512");
    }

    @Test
    @DisplayName("/.well-known/jwks.json publishes RSA public key with kid+alg")
    @SuppressWarnings("unchecked")
    void jwksPublishesRsaKey() {
        ResponseEntity<Map<String, Object>> resp = controller.jwks();
        assertThat(resp.getBody()).isNotNull();
        List<Map<String, Object>> keys = (List<Map<String, Object>>) resp.getBody().get("keys");
        assertThat(keys).hasSize(1);
        Map<String, Object> jwk = keys.get(0);
        assertThat(jwk).containsEntry("kty", "RSA");
        assertThat(jwk).containsEntry("alg", "RS256");
        assertThat(jwk).containsEntry("use", "sig");
        assertThat(jwk).containsEntry("kid", RsaKeyProvider.DEFAULT_KID);
        assertThat(jwk.get("n")).isInstanceOf(String.class);
        assertThat((String) jwk.get("n")).isNotBlank();
        assertThat(jwk.get("e")).isInstanceOf(String.class);
        assertThat((String) jwk.get("e")).isNotBlank();
        // HS512 symmetric secret must never appear in JWKS
        assertThat(jwk).doesNotContainKey("k");
        assertThat(jwk.get("kty")).isNotEqualTo("oct");
    }
}
