package com.fivucsas.identity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * T3.C — HS512 key registry / parallel-verify rotation.
 *
 * <p>Covers the rollout sequence described in
 * {@code ANALYSIS_2026-05-02_USER_DOMAIN_AND_JWT_ROTATION.md} §JWT_SECRET rotation:
 * <ol>
 *   <li>Add a new HS key via {@code JWT_HS_KEY_<KID>} env (here, MockEnvironment property).</li>
 *   <li>Restart with the new kid in {@code app.security.jwt.retired-hs-kids}.</li>
 *   <li>Tokens minted with either kid keep verifying; new tokens still carry
 *       the old (active) kid until the operator flips
 *       {@code app.security.jwt.active-hs-kid}.</li>
 *   <li>After flip, freshly-minted tokens carry the new kid; tokens minted
 *       before the flip continue to verify against the old kid (now retired).</li>
 * </ol>
 *
 * <p>The HS512 verification path is always opted-in here ({@code allowHs512=true})
 * — its default-off security posture is exercised in
 * {@link JwtServiceSecurityHardeningTest}.
 */
@DisplayName("JwtService — HS-key registry parallel-verify rotation (T3.C)")
class JwtServiceKeyRegistryTest {

    private static final String TEST_EMAIL = "rotate@fivucsas.com";

    /** Pre-rotation key — base64-encoded random 64 bytes. */
    private static final String OLD_SECRET =
            "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMjU2LWJpdHMtbG9uZy1mb3ItaHMyNTYtYWxnb3JpdGhtLXNlY3VyaXR5LXJlcXVpcmVtZW50cw==";
    /** Post-rotation key — different base64 payload, also >= 64 bytes. */
    private static final String NEW_SECRET =
            "Y29tcGxldGVseS1uZXctc2VjcmV0LWZvci1qd3Qtcm90YXRpb24tdGVzdC1tdXN0LWJlLWF0LWxlYXN0LTI1Ni1iaXRzLWxvbmctZm9yLWhzNTEy";

    private static final String OLD_KID = "hs-2026-04";
    private static final String NEW_KID = "hs-2026-05";

    /**
     * Build a {@link JwtService} wired to an {@link HsKeyRegistry} that mirrors
     * the env-driven config: per-kid secrets are exposed via Spring property
     * keys ({@code app.security.jwt.hs-key.<kid>}) so tests don't need to touch
     * the OS environment.
     */
    private JwtService buildService(String activeKid, String retiredKidsCsv) {
        // Legacy JWT_SECRET fallback — only consulted when the active kid has no
        // per-kid env var. Tests that exercise the fallback assert this; tests
        // that don't should still pass even if the mock returns this value.
        JwtSecretProvider legacyProvider = mock(JwtSecretProvider.class);
        lenient().when(legacyProvider.getSecret()).thenReturn(OLD_SECRET);

        MockEnvironment env = new MockEnvironment();
        env.setProperty("app.security.jwt.hs-key." + OLD_KID, OLD_SECRET);
        env.setProperty("app.security.jwt.hs-key." + NEW_KID, NEW_SECRET);

        HsKeyRegistry registry = new HsKeyRegistry(legacyProvider, env);
        ReflectionTestUtils.setField(registry, "activeHsKid", activeKid);
        ReflectionTestUtils.setField(registry, "retiredHsKidsCsv",
                retiredKidsCsv == null ? "" : retiredKidsCsv);
        registry.initialize();

        RsaKeyProvider rsa = JwtAlgoTestSupport.newRsaKeyProvider();
        JwtService svc = new JwtService(registry, rsa, new MockEnvironment());
        ReflectionTestUtils.setField(svc, "jwtExpiration", 900_000L);
        ReflectionTestUtils.setField(svc, "defaultAlgo", "HS512");
        ReflectionTestUtils.setField(svc, "allowHs512", true);
        ReflectionTestUtils.setField(svc, "expectedIssuer", "");
        return svc;
    }

    /** Mint an HS512 token with arbitrary kid, signed by an arbitrary base64 secret. */
    private static String mintToken(String secretB64, String kid) {
        byte[] bytes = Decoders.BASE64.decode(secretB64);
        SecretKey key = Keys.hmacShaKeyFor(bytes);
        return Jwts.builder()
                .header().keyId(kid).and()
                .subject(TEST_EMAIL)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    // ─────────────────────────────────────────────────────────────────
    // Rollout phase 1 — new key registered, old kid still active
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Phase 1: old kid active + new kid retired -> both verify")
    void phase1_oldActive_newRetired_bothVerify() {
        // active=OLD, retired=NEW. (Equivalent to the prod state right after
        // step 2 of the rollout: new key is registered but signing hasn't
        // flipped yet. We model "phase 1 = both kids in registry" by listing
        // the new kid as retired even though chronologically it's the future
        // active key — the registry only cares that both keys are present.)
        JwtService svc = buildService(OLD_KID, NEW_KID);

        String oldTok = mintToken(OLD_SECRET, OLD_KID);
        String newTok = mintToken(NEW_SECRET, NEW_KID);

        assertThat(svc.extractEmail(oldTok)).isEqualTo(TEST_EMAIL);
        assertThat(svc.extractEmail(newTok)).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Phase 1: new tokens minted by service still carry old kid")
    void phase1_freshTokenStampsOldKid() {
        JwtService svc = buildService(OLD_KID, NEW_KID);

        String fresh = svc.generateAccessToken(TEST_EMAIL);

        // Header kid should still be OLD_KID — flipping it requires changing
        // active-hs-kid (phase 2).
        String headerJson = decodeHeader(fresh);
        assertThat(headerJson).contains("\"kid\":\"" + OLD_KID + "\"");
        assertThat(svc.extractEmail(fresh)).isEqualTo(TEST_EMAIL);
    }

    // ─────────────────────────────────────────────────────────────────
    // Rollout phase 2 — active flipped to new kid, old kid retired
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Phase 2: token signed with old kid still verifies after rotation")
    void phase2_oldTokenVerifiesAfterFlip() {
        JwtService svc = buildService(NEW_KID, OLD_KID);

        // Token minted before the flip (carries OLD_KID).
        String preFlip = mintToken(OLD_SECRET, OLD_KID);

        assertThat(svc.extractEmail(preFlip)).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Phase 2: freshly-minted token carries new kid")
    void phase2_freshTokenCarriesNewKid() {
        JwtService svc = buildService(NEW_KID, OLD_KID);

        String fresh = svc.generateAccessToken(TEST_EMAIL);

        String headerJson = decodeHeader(fresh);
        assertThat(headerJson).contains("\"kid\":\"" + NEW_KID + "\"");
        assertThat(svc.extractEmail(fresh)).isEqualTo(TEST_EMAIL);
    }

    @Test
    @DisplayName("Phase 2: token signed with new kid verifies")
    void phase2_newTokenVerifies() {
        JwtService svc = buildService(NEW_KID, OLD_KID);

        String tok = mintToken(NEW_SECRET, NEW_KID);

        assertThat(svc.extractEmail(tok)).isEqualTo(TEST_EMAIL);
    }

    // ─────────────────────────────────────────────────────────────────
    // Negative cases
    // ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Token with unknown kid is rejected")
    void unknownKidRejected() {
        JwtService svc = buildService(OLD_KID, "");

        // Sign with a kid the registry doesn't know about.
        String forged = mintToken(OLD_SECRET, "hs-2099-12");

        assertThatThrownBy(() -> svc.extractEmail(forged))
                .isInstanceOf(SignatureException.class)
                .hasMessageContaining("Unknown JWT key id: hs-2099-12");
    }

    @Test
    @DisplayName("Adding the new kid as retired does NOT change the active signing kid")
    void addingRetiredKidDoesNotFlipActive() {
        // Precondition: rotation is half-rolled — new key registered but
        // active-hs-kid not yet flipped. Service should still mint with OLD.
        JwtService svc = buildService(OLD_KID, NEW_KID);

        String fresh = svc.generateAccessToken(TEST_EMAIL);

        assertThat(decodeHeader(fresh))
                .contains("\"kid\":\"" + OLD_KID + "\"")
                .doesNotContain("\"kid\":\"" + NEW_KID + "\"");
    }

    // ─────────────────────────────────────────────────────────────────
    // Backward-compat: env unset -> defaults
    // ─────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Backward compat: registry defaults when env vars unset")
    class BackwardCompat {

        @Test
        @DisplayName("active-hs-kid unset -> defaults to legacy hs-2026-04 + JWT_SECRET fallback")
        void defaultsToLegacyJwtSecret() {
            // Don't set per-kid env vars. The registry should fall back to the
            // legacy JwtSecretProvider for the (default-named) active kid, and
            // signing/verifying must still work — exactly the pre-registry
            // behaviour.
            JwtSecretProvider legacy = mock(JwtSecretProvider.class);
            lenient().when(legacy.getSecret()).thenReturn(OLD_SECRET);
            HsKeyRegistry registry = new HsKeyRegistry(legacy, new MockEnvironment());
            // Defaults: activeHsKid -> DEFAULT_ACTIVE_KID, retired -> empty.
            ReflectionTestUtils.setField(registry, "activeHsKid",
                    HsKeyRegistry.DEFAULT_ACTIVE_KID);
            ReflectionTestUtils.setField(registry, "retiredHsKidsCsv", "");
            registry.initialize();

            assertThat(registry.getActiveKid())
                    .isEqualTo(HsKeyRegistry.DEFAULT_ACTIVE_KID);
            assertThat(registry.allKids())
                    .containsExactly(HsKeyRegistry.DEFAULT_ACTIVE_KID);

            // End-to-end round trip via JwtService.
            RsaKeyProvider rsa = JwtAlgoTestSupport.newRsaKeyProvider();
            JwtService svc = new JwtService(registry, rsa, new MockEnvironment());
            ReflectionTestUtils.setField(svc, "jwtExpiration", 900_000L);
            ReflectionTestUtils.setField(svc, "defaultAlgo", "HS512");
            ReflectionTestUtils.setField(svc, "allowHs512", true);
            ReflectionTestUtils.setField(svc, "expectedIssuer", "");

            String tok = svc.generateAccessToken(TEST_EMAIL);
            assertThat(svc.extractEmail(tok)).isEqualTo(TEST_EMAIL);
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────

    private static String decodeHeader(String compactJws) {
        String[] parts = compactJws.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("not a JWS compact token");
        }
        return new String(java.util.Base64.getUrlDecoder().decode(parts[0]),
                java.nio.charset.StandardCharsets.UTF_8);
    }
}
