package com.fivucsas.identity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * BE-H1 — Dual-algorithm JWT coexistence tests.
 *
 * Verifies that:
 * - HS512 tokens (legacy) still validate
 * - RS256 tokens issue and validate
 * - Tokens with an unknown kid are rejected
 * - Switching default-algo emits tokens with the correct kid
 */
@DisplayName("JWT dual-algorithm coexistence (BE-H1)")
class JwtDualAlgoTest {

    private static final String TEST_EMAIL = "dual@fivucsas.com";
    private static final String TEST_SECRET =
            "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZy1mb3ItaHMyNTYtYWxnb3JpdGhtLXNlY3VyaXR5LXJlcXVpcmVtZW50cw==";

    private RsaKeyProvider rsa;
    private JwtSecretProvider hmacProvider;
    private JwtService service;

    @BeforeEach
    void setUp() {
        hmacProvider = mock(JwtSecretProvider.class);
        when(hmacProvider.getSecret()).thenReturn(TEST_SECRET);
        rsa = JwtAlgoTestSupport.newRsaKeyProvider();
        service = new JwtService(hmacProvider, rsa, new MockEnvironment());
        ReflectionTestUtils.setField(service, "jwtExpiration", 900_000L);
        ReflectionTestUtils.setField(service, "defaultAlgo", "HS512");
    }

    @Test
    @DisplayName("HS512 default: legacy tokens validate end-to-end")
    void hs512DefaultValidates() {
        String token = service.generateAccessToken(TEST_EMAIL);
        assertThat(service.extractEmail(token)).isEqualTo(TEST_EMAIL);
        assertThat(service.isTokenValid(token, TEST_EMAIL)).isTrue();
    }

    @Test
    @DisplayName("RS256 default: issues RS256 token that validates")
    void rs256IssuesAndValidates() {
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");
        String token = service.generateAccessToken(TEST_EMAIL);
        assertThat(service.extractEmail(token)).isEqualTo(TEST_EMAIL);
        assertThat(service.isTokenValid(token, TEST_EMAIL)).isTrue();
    }

    @Test
    @DisplayName("Verifier accepts BOTH algos simultaneously")
    void verifierAcceptsBothAlgos() {
        // Mint HS512
        ReflectionTestUtils.setField(service, "defaultAlgo", "HS512");
        String hs = service.generateAccessToken(TEST_EMAIL);

        // Mint RS256
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");
        String rsToken = service.generateAccessToken(TEST_EMAIL);

        // Both validate regardless of current default
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");
        assertThat(service.isTokenValid(hs, TEST_EMAIL)).isTrue();
        assertThat(service.isTokenValid(rsToken, TEST_EMAIL)).isTrue();
    }

    @Test
    @DisplayName("Legacy HS512 tokens with NO kid still validate (backward compat)")
    void legacyNoKidStillValidates() {
        byte[] bytes = io.jsonwebtoken.io.Decoders.BASE64.decode(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(bytes);
        String legacy = Jwts.builder()
                .subject(TEST_EMAIL)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();

        assertThat(service.extractEmail(legacy)).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Unknown kid is rejected")
    void unknownKidRejected() {
        byte[] bytes = io.jsonwebtoken.io.Decoders.BASE64.decode(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(bytes);
        String bogusKid = Jwts.builder()
                .header().keyId("unknown-kid-xyz").and()
                .subject(TEST_EMAIL)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();

        assertThatThrownBy(() -> service.extractEmail(bogusKid))
                .isInstanceOf(SignatureException.class)
                .hasMessageContaining("Unknown JWT key id");
    }
}
