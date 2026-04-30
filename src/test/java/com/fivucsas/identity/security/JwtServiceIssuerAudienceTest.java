package com.fivucsas.identity.security;

import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MissingClaimException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * AUDIT_2026-04-30 P1.6 — RFC 7519 §4.1.1 / §4.1.3 enforcement.
 *
 * Before this fix, {@link JwtService#isTokenValid(String, String)} only checked
 * subject equality + expiration. Tokens with the wrong (or missing) issuer or
 * audience were silently accepted, allowing JWTs minted by another tenant or a
 * shared HMAC secret-leak victim to pass auth. This suite verifies:
 *
 * <ol>
 *   <li>Tokens minted by the service carry the configured iss + aud.</li>
 *   <li>Mint-and-validate round-trip succeeds for both RS256 and HS512.</li>
 *   <li>A forged token with a different iss is rejected.</li>
 *   <li>A forged token with a different aud is rejected.</li>
 *   <li>A token missing iss is rejected.</li>
 *   <li>A token missing aud is rejected.</li>
 *   <li>The HS512 null-kid backward-compat path is held to the same iss+aud
 *       contract — it is not a soft fallback.</li>
 * </ol>
 *
 * Forged tokens are minted with the same HMAC secret + RSA private key the
 * service trusts, so signature verification passes and the test really exercises
 * the iss/aud claim-requirement path (not signature failure).
 */
@DisplayName("JwtService — iss + aud enforcement (P1.6)")
class JwtServiceIssuerAudienceTest {

    private static final String TEST_EMAIL = "issaud@fivucsas.com";
    private static final String TEST_SECRET =
            "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZy1mb3ItaHMyNTYtYWxnb3JpdGhtLXNlY3VyaXR5LXJlcXVpcmVtZW50cw==";
    private static final String TEST_ISSUER = "https://api.fivucsas.com";
    private static final String TEST_AUDIENCE = "fivucsas-api";

    private JwtSecretProvider hmacProvider;
    private RsaKeyProvider rsa;
    private JwtService service;

    @BeforeEach
    void setUp() {
        hmacProvider = mock(JwtSecretProvider.class);
        when(hmacProvider.getSecret()).thenReturn(TEST_SECRET);
        rsa = JwtAlgoTestSupport.newRsaKeyProvider();
        service = new JwtService(hmacProvider, rsa, new MockEnvironment());
        ReflectionTestUtils.setField(service, "jwtExpiration", 900_000L);
        ReflectionTestUtils.setField(service, "defaultAlgo", "HS512");
        ReflectionTestUtils.setField(service, "issuer", TEST_ISSUER);
        ReflectionTestUtils.setField(service, "audience", TEST_AUDIENCE);
    }

    // ============== HAPPY PATH ==============

    @Test
    @DisplayName("Mint with HS512: iss + aud are present and parse validates")
    void hs512MintAndValidate() {
        String token = service.generateAccessToken(TEST_EMAIL);
        assertThat(service.isTokenValid(token, TEST_EMAIL)).isTrue();
    }

    @Test
    @DisplayName("Mint with RS256: iss + aud are present and parse validates")
    void rs256MintAndValidate() {
        ReflectionTestUtils.setField(service, "defaultAlgo", "RS256");
        String token = service.generateAccessToken(TEST_EMAIL);
        assertThat(service.isTokenValid(token, TEST_EMAIL)).isTrue();
    }

    // ============== ISSUER MISMATCH / MISSING ==============

    @Test
    @DisplayName("HS512: token with WRONG issuer is rejected (IncorrectClaimException)")
    void hs512WrongIssuerRejected() {
        String forged = forgedHs(TEST_EMAIL, "https://evil.example", TEST_AUDIENCE, HS_KID());
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    @DisplayName("RS256: token with WRONG issuer is rejected (IncorrectClaimException)")
    void rs256WrongIssuerRejected() {
        String forged = forgedRs(TEST_EMAIL, "https://evil.example", TEST_AUDIENCE);
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    @DisplayName("HS512: token MISSING issuer is rejected (MissingClaimException)")
    void hs512MissingIssuerRejected() {
        String forged = forgedHs(TEST_EMAIL, null, TEST_AUDIENCE, HS_KID());
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(MissingClaimException.class);
    }

    // ============== AUDIENCE MISMATCH / MISSING ==============

    @Test
    @DisplayName("HS512: token with WRONG audience is rejected (IncorrectClaimException)")
    void hs512WrongAudienceRejected() {
        String forged = forgedHs(TEST_EMAIL, TEST_ISSUER, "other-api", HS_KID());
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    @DisplayName("RS256: token with WRONG audience is rejected (IncorrectClaimException)")
    void rs256WrongAudienceRejected() {
        String forged = forgedRs(TEST_EMAIL, TEST_ISSUER, "other-api");
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    @DisplayName("HS512: token MISSING audience is rejected (MissingClaimException)")
    void hs512MissingAudienceRejected() {
        String forged = forgedHs(TEST_EMAIL, TEST_ISSUER, null, HS_KID());
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(MissingClaimException.class);
    }

    // ============== HS512 NULL-KID FALLBACK PARITY ==============

    @Test
    @DisplayName("HS512 null-kid backward-compat path: still rejects WRONG iss")
    void nullKidStillRejectsWrongIss() {
        String forged = forgedHs(TEST_EMAIL, "https://evil.example", TEST_AUDIENCE, null);
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    @DisplayName("HS512 null-kid backward-compat path: still rejects WRONG aud")
    void nullKidStillRejectsWrongAud() {
        String forged = forgedHs(TEST_EMAIL, TEST_ISSUER, "other-api", null);
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(IncorrectClaimException.class);
    }

    @Test
    @DisplayName("HS512 null-kid backward-compat path: still rejects MISSING iss/aud")
    void nullKidStillRejectsMissingClaims() {
        String forged = forgedHs(TEST_EMAIL, null, null, null);
        // Either MissingClaimException for iss or aud — both are JwtException subtypes.
        assertThatThrownBy(() -> service.isTokenValid(forged, TEST_EMAIL))
                .isInstanceOf(MissingClaimException.class);
    }

    // ============== HELPERS ==============

    private static String HS_KID() {
        return JwtService.HS_KID;
    }

    /** Forge a token signed with the same HMAC secret the service trusts. */
    private String forgedHs(String email, String iss, String aud, String kid) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
        var b = Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000));
        if (kid != null) {
            b = b.header().keyId(kid).and();
        }
        if (iss != null) {
            b = b.issuer(iss);
        }
        if (aud != null) {
            b = b.audience().add(aud).and();
        }
        return b.signWith(key, Jwts.SIG.HS512).compact();
    }

    /** Forge a token signed with the same RSA private key the service trusts. */
    private String forgedRs(String email, String iss, String aud) {
        PrivateKey priv = rsa.getPrivateKey();
        var b = Jwts.builder()
                .header().keyId(rsa.getKid()).and()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000));
        if (iss != null) {
            b = b.issuer(iss);
        }
        if (aud != null) {
            b = b.audience().add(aud).and();
        }
        return b.signWith(priv, Jwts.SIG.RS256).compact();
    }
}
