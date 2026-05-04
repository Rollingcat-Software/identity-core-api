package com.fivucsas.identity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MissingClaimException;
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
 * SECURITY_REVIEW_2026-05-01 §P0-3 / §P2-3 / §P1-5 hardening tests.
 *
 * <p>Covers:
 * <ul>
 *   <li>HS512 verification path is OFF by default (P0-3 code half).</li>
 *   <li>alg-vs-kid binding rejects forged header pairs (P2-3, CVE-2018-0114
 *       shape).</li>
 *   <li>Issuer claim is required when configured (P1-5).</li>
 * </ul>
 */
@DisplayName("JwtService — security hardening (§P0-3 / §P2-3 / §P1-5)")
class JwtServiceSecurityHardeningTest {

    private static final String TEST_EMAIL = "harden@fivucsas.com";
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
        HsKeyRegistry registry = JwtAlgoTestSupport.newHsKeyRegistry(hmacProvider);
        service = new JwtService(registry, rsa, new MockEnvironment());
        ReflectionTestUtils.setField(service, "jwtExpiration", 900_000L);
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");
        // Default-off: this is the prod posture per §P0-3.
        ReflectionTestUtils.setField(service, "allowHs512", false);
        ReflectionTestUtils.setField(service, "expectedIssuer", "");
    }

    // ─────────────────────────────────────────────────────────────────
    // §P0-3 code half: HS512 verification path is off by default
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("HS512 token rejected when allow-hs512=false (default)")
    void hs512RejectedByDefault() {
        String hsToken = mintHs512Token(TEST_EMAIL, HS_KID());

        assertThatThrownBy(() -> service.extractEmail(hsToken))
                .isInstanceOf(SignatureException.class)
                .hasMessageContaining("HS512 verification disabled");
    }

    @Test
    @DisplayName("Legacy no-kid HS512 token rejected when allow-hs512=false")
    void legacyNoKidRejectedByDefault() {
        byte[] bytes = io.jsonwebtoken.io.Decoders.BASE64.decode(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(bytes);
        String legacy = Jwts.builder()
                .subject(TEST_EMAIL)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();

        assertThatThrownBy(() -> service.extractEmail(legacy))
                .isInstanceOf(SignatureException.class)
                .hasMessageContaining("HS512 verification disabled");
    }

    @Test
    @DisplayName("HS512 token accepted when allow-hs512=true (rollback flag)")
    void hs512AcceptedWhenFlagOn() {
        ReflectionTestUtils.setField(service, "allowHs512", true);
        String hsToken = mintHs512Token(TEST_EMAIL, HS_KID());

        assertThat(service.extractEmail(hsToken)).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("RS256 token still validates regardless of allow-hs512 flag")
    void rs256AlwaysValidates() {
        String rsToken = service.generateAccessToken(TEST_EMAIL);
        assertThat(service.extractEmail(rsToken)).isEqualTo(TEST_EMAIL);
    }

    // ─────────────────────────────────────────────────────────────────
    // §P2-3: alg-vs-kid binding (CVE-2018-0114 shape)
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Forged header: kid=hs but alg=RS256 -> rejected")
    void forgedHsKidWithRsAlgRejected() {
        // Allow HS512 path so the keyLocator routes by kid; with the alg
        // header pretending to be RS256, the alg-vs-kid check must fire.
        ReflectionTestUtils.setField(service, "allowHs512", true);

        // Build an attacker-shaped token. Note: JJWT's signing API sets the
        // alg header from the key, so we can't ship a real "kid=hs/alg=RS256"
        // from one signWith call. Instead, sign with HS512 (so the body+sig
        // are valid for the HMAC key) but rewrite the header to claim alg=RS256
        // before parse. This is exactly the forge surface §P2-3 closes.
        byte[] bytes = io.jsonwebtoken.io.Decoders.BASE64.decode(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(bytes);
        String real = Jwts.builder()
                .header().keyId(HS_KID()).and()
                .subject(TEST_EMAIL)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();
        String forged = rewriteHeader(real, "{\"kid\":\"" + HS_KID() + "\",\"alg\":\"RS256\"}");

        assertThatThrownBy(() -> service.extractEmail(forged))
                .isInstanceOf(SignatureException.class)
                .hasMessageContaining("alg/kid mismatch");
    }

    @Test
    @DisplayName("Forged header: kid=rsa but alg=HS512 -> rejected")
    void forgedRsaKidWithHsAlgRejected() {
        // Generate an RS256 token, then rewrite the alg header to HS512.
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");
        String real = service.generateAccessToken(TEST_EMAIL);
        String forged = rewriteHeader(real,
                "{\"kid\":\"" + rsa.getKid() + "\",\"alg\":\"HS512\"}");

        assertThatThrownBy(() -> service.extractEmail(forged))
                .isInstanceOf(SignatureException.class)
                .hasMessageContaining("alg/kid mismatch");
    }

    // ─────────────────────────────────────────────────────────────────
    // §P1-5: issuer claim required when configured
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Issuer required: token without iss claim -> rejected")
    void issuerRequiredButMissing() {
        // Mint a token WITHOUT issuer (issuer config empty), then turn the
        // requirement on for verification.
        String token = service.generateAccessToken(TEST_EMAIL);
        ReflectionTestUtils.setField(service, "expectedIssuer", "https://api.fivucsas.com");

        assertThatThrownBy(() -> service.extractEmail(token))
                .isInstanceOfAny(MissingClaimException.class,
                        io.jsonwebtoken.IncorrectClaimException.class);
    }

    @Test
    @DisplayName("Issuer required: matching iss -> accepted")
    void issuerRequiredAndMatches() {
        ReflectionTestUtils.setField(service, "expectedIssuer", "https://api.fivucsas.com");
        // Re-mint so the new issuer claim is stamped on the token.
        String token = service.generateAccessToken(TEST_EMAIL);

        assertThat(service.extractEmail(token)).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Issuer required: wrong iss -> rejected")
    void issuerRequiredAndMismatches() {
        ReflectionTestUtils.setField(service, "expectedIssuer", "https://api.fivucsas.com");
        String token = service.generateAccessToken(TEST_EMAIL);

        // Now flip the expected issuer; the token's iss no longer matches.
        ReflectionTestUtils.setField(service, "expectedIssuer", "https://different.example.com");

        assertThatThrownBy(() -> service.extractEmail(token))
                .isInstanceOf(io.jsonwebtoken.IncorrectClaimException.class);
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────

    private static String HS_KID() {
        return JwtService.HS_KID;
    }

    private String mintHs512Token(String subject, String kid) {
        byte[] bytes = io.jsonwebtoken.io.Decoders.BASE64.decode(TEST_SECRET);
        SecretKey key = Keys.hmacShaKeyFor(bytes);
        return Jwts.builder()
                .header().keyId(kid).and()
                .subject(subject)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Rewrites the header segment of a JWS in compact form to {@code newHeaderJson},
     * preserving the existing payload and signature. Used to construct forged
     * tokens where the header claims a different alg than what was actually
     * signed.
     */
    private static String rewriteHeader(String jwt, String newHeaderJson) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("not a JWS compact token");
        }
        String b64Header = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(newHeaderJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return b64Header + "." + parts[1] + "." + parts[2];
    }
}
