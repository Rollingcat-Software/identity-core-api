package com.fivucsas.identity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MissingClaimException;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 — pin the {@code aud} claim
 * binding so the fix doesn't disappear a fourth time (missed on 2026-04-20,
 * 2026-05-02, 2026-05-12). Also covers the §P1 revoked-kid list and the
 * prod-profile boot assertion.
 */
@DisplayName("JwtService — audience binding + revoked kids (2026-05-12)")
class JwtServiceAudienceTest {

    private static final String TEST_EMAIL = "aud@fivucsas.com";
    private static final String TEST_SECRET =
            "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZy1mb3ItaHMyNTYtYWxnb3JpdGhtLXNlY3VyaXR5LXJlcXVpcmVtZW50cw==";
    private static final String EXPECTED_AUD = "fivucsas-api";

    private JwtSecretProvider hmacProvider;
    private RsaKeyProvider rsa;
    private JwtService service;

    @BeforeEach
    void setUp() {
        hmacProvider = mock(JwtSecretProvider.class);
        when(hmacProvider.getSecret()).thenReturn(TEST_SECRET);
        rsa = JwtAlgoTestSupport.newRsaKeyProvider();
        HsKeyRegistry registry = JwtAlgoTestSupport.newHsKeyRegistry(hmacProvider);
        service = new JwtService(registry, rsa, new MockEnvironment());
        ReflectionTestUtils.setField(service, "jwtExpiration", 900_000L);
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");
        ReflectionTestUtils.setField(service, "allowHs512", false);
        ReflectionTestUtils.setField(service, "expectedIssuer", "");
        ReflectionTestUtils.setField(service, "expectedAudience", EXPECTED_AUD);
        ReflectionTestUtils.setField(service, "revokedKids", Collections.emptySet());
    }

    // ─────────────────────────────────────────────────────────────────
    // §aud-claim — minted tokens carry it, parser requires it
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Minted access token contains the aud claim")
    void mintedTokenCarriesAud() {
        String tok = service.generateAccessToken(TEST_EMAIL);

        // Decode the payload directly to be sure the claim is wire-present
        // (not just visible through our own parser, which could itself drop it).
        String payloadJson = decodePayload(tok);
        assertThat(payloadJson).contains("\"aud\"");
        assertThat(payloadJson).contains(EXPECTED_AUD);
    }

    @Test
    @DisplayName("Round-trip: extractEmail succeeds when token aud matches config")
    void audMatchRoundTrip() {
        String tok = service.generateAccessToken(TEST_EMAIL);
        assertThat(service.extractEmail(tok)).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Token minted without aud is rejected when audience is required")
    void missingAudRejected() {
        // Mint a token while audience requirement is off, then turn it on.
        ReflectionTestUtils.setField(service, "expectedAudience", "");
        String tok = service.generateAccessToken(TEST_EMAIL);
        ReflectionTestUtils.setField(service, "expectedAudience", EXPECTED_AUD);

        assertThatThrownBy(() -> service.extractEmail(tok))
                .isInstanceOfAny(MissingClaimException.class, IncorrectClaimException.class);
    }

    @Test
    @DisplayName("Token whose aud does not contain configured audience is rejected")
    void mismatchedAudRejected() {
        // Mint with one audience, verify with another.
        String tok = service.generateAccessToken(TEST_EMAIL);
        ReflectionTestUtils.setField(service, "expectedAudience", "some-other-aud");

        assertThatThrownBy(() -> service.extractEmail(tok))
                .isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    @DisplayName("Empty audience config disables the requirement (dev profile parity)")
    void emptyAudIsPermissive() {
        // Mint without aud, parse without requireAudience -> must succeed.
        ReflectionTestUtils.setField(service, "expectedAudience", "");
        String tok = service.generateAccessToken(TEST_EMAIL);
        assertThat(service.extractEmail(tok)).isEqualTo(TEST_EMAIL);
    }

    // ─────────────────────────────────────────────────────────────────
    // §P1 — explicit revoked-kid list (defence-in-depth for hs-2026-04)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Token signed with revoked kid hs-2026-04 is rejected even if allow-hs512=true")
    void revokedKidRejectedEvenIfHs512Allowed() {
        // Simulate emergency rollback: HS512 is back on, but the leaked
        // hs-2026-04 secret is explicitly revoked. The token must still fail.
        ReflectionTestUtils.setField(service, "allowHs512", true);
        ReflectionTestUtils.setField(service, "revokedKids", Set.of("hs-2026-04"));
        // Disable audience so we hit the revoked-kid branch (audience would
        // fire first on a token that also lacks aud).
        ReflectionTestUtils.setField(service, "expectedAudience", "");

        byte[] bytes = io.jsonwebtoken.io.Decoders.BASE64.decode(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(bytes);
        String hsToken = Jwts.builder()
                .header().keyId("hs-2026-04").and()
                .subject(TEST_EMAIL)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();

        assertThatThrownBy(() -> service.extractEmail(hsToken))
                .isInstanceOf(SignatureException.class)
                .hasMessageContaining("revoked JWT kid");
    }

    @Test
    @DisplayName("Empty revoked-kid set leaves all kids verifiable")
    void emptyRevokedSetIsPermissive() {
        ReflectionTestUtils.setField(service, "revokedKids", Collections.emptySet());
        String tok = service.generateAccessToken(TEST_EMAIL);
        // RS256 token, kid = rsaKeyProvider.getKid(). Should round-trip cleanly.
        assertThat(service.extractEmail(tok)).isEqualTo(TEST_EMAIL);
    }

    // ─────────────────────────────────────────────────────────────────
    // Prod-profile assertion: blank audience must fail boot
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Prod profile + blank audience -> boot fails")
    void prodProfileBlankAudienceFails() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        JwtService prodSvc = new JwtService(
                JwtAlgoTestSupport.newHsKeyRegistry(hmacProvider),
                rsa,
                env);
        ReflectionTestUtils.setField(prodSvc, "expectedAudience", "");

        assertThatThrownBy(prodSvc::assertProdAudienceIsConfigured)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("audience is blank");
    }

    @Test
    @DisplayName("Prod profile + configured audience -> boot ok")
    void prodProfileConfiguredAudienceOk() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        JwtService prodSvc = new JwtService(
                JwtAlgoTestSupport.newHsKeyRegistry(hmacProvider),
                rsa,
                env);
        ReflectionTestUtils.setField(prodSvc, "expectedAudience", EXPECTED_AUD);

        // Must NOT throw.
        prodSvc.assertProdAudienceIsConfigured();
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────

    private static String decodePayload(String compactJws) {
        String[] parts = compactJws.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("not a JWS compact token");
        }
        return new String(
                java.util.Base64.getUrlDecoder().decode(parts[1]),
                java.nio.charset.StandardCharsets.UTF_8);
    }
}
