package com.fivucsas.identity.security;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * JWT sign + verify service supporting dual-algorithm coexistence (BE-H1):
 *
 * - HS512 (legacy, symmetric) — kid = "hs-2026-04"
 * - RS256 (asymmetric, OIDC best practice) — kid = RsaKeyProvider.getKid()
 *
 * Signing algorithm is selected by {@code fivucsas.jwt.default-algo}
 * (default HS512 during the coexistence window; flip to RS256 after soak).
 *
 * Verification inspects the incoming JWS header "kid" and routes to the
 * matching key. Tokens without a recognised kid are rejected.
 */
@Service
@Slf4j
@Primary
public class JwtService implements TokenGenerationPort {

    /**
     * Historical default kid for HS512 tokens. Kept for backward compatibility
     * with callers that reference the constant directly (e.g. test harnesses).
     * The actual signing kid is read from {@link HsKeyRegistry#getActiveKid()}
     * which defaults to this value when {@code app.security.jwt.active-hs-kid}
     * is unset.
     */
    public static final String HS_KID = HsKeyRegistry.DEFAULT_ACTIVE_KID;

    private final HsKeyRegistry hsKeyRegistry;
    private final RsaKeyProvider rsaKeyProvider;
    private final Environment environment;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${fivucsas.jwt.default-algo:HS512}")
    private String defaultAlgo;

    /**
     * P0-3 code half (SECURITY_REVIEW_2026-05-01 §P0-3): the leaked
     * f8ee668:.env.gcp HS512 secret keeps the HS512 verification path a
     * forge surface. RS256 has been the prod default since 2026-04-20, so
     * accept HS512 tokens only when an operator explicitly opts in (e.g.
     * an emergency rollback window). Default OFF — any HS512 token is
     * rejected with a SignatureException at parse time.
     */
    @Value("${app.security.jwt.allow-hs512:false}")
    private boolean allowHs512;

    /**
     * P1-5 / §P0-3 fix: bind {@code iss} on the parser. Empty value disables
     * the requirement (kept open for the dev profile where the issuer URL
     * isn't pinned).
     */
    @Value("${app.security.jwt.issuer:}")
    private String expectedIssuer;

    /**
     * SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 — bind {@code aud} (RFC 7519
     * §4.1.3). Memory has missed this fix three times (2026-04-20, 2026-05-02,
     * 2026-05-12). Tokens now carry an {@code aud} claim, and the parser
     * requires that the configured audience appears in the token's {@code aud}
     * set (single-string for now, comma-separated for future multi-tenant
     * audiences). Empty value disables the requirement for dev/test parity
     * with {@link #expectedIssuer}.
     */
    @Value("${app.security.jwt.audience:}")
    private String expectedAudience;

    /**
     * SECURITY_REVIEW 2026-05-12 §P1 — explicitly revoked HS512 kids. The
     * leaked f8ee668:.env.gcp secret tagged {@code hs-2026-04} should be
     * rejected even if {@link #allowHs512} is somehow flipped back on for an
     * emergency rollback window. Comma-separated list of kid strings; default
     * empty so non-prod profiles stay unaffected.
     */
    @Value("${app.security.jwt.revoked-kids:}")
    private String revokedKidsCsv;

    private Set<String> revokedKids = Collections.emptySet();

    public JwtService(HsKeyRegistry hsKeyRegistry,
                      RsaKeyProvider rsaKeyProvider,
                      Environment environment) {
        this.hsKeyRegistry = hsKeyRegistry;
        this.rsaKeyProvider = rsaKeyProvider;
        this.environment = environment;
    }

    /**
     * AUDIT_2026-04-28_SECURITY.md SEC-P1 #3: when the {@code prod} profile
     * is active the signing algorithm MUST be RS256. application-prod.yml
     * pins it but a misconfigured deploy could still flip it via the
     * {@code JWT_DEFAULT_ALGO} env var or a stray {@code @PropertySource}.
     * Fail fast at startup rather than silently mint HS512 tokens in prod.
     */
    @PostConstruct
    void logSigningPosture() {
        if (allowHs512) {
            log.warn("SECURITY: app.security.jwt.allow-hs512=true — HS512 token "
                    + "verification is enabled. RS256 has been the prod default since "
                    + "2026-04-20; flip this back to false unless rolling back.");
        } else {
            log.info("JWT verification: HS512 path DISABLED (P0-3 code-side closure); "
                    + "RS256-only via kid={}", rsaKeyProvider != null ? rsaKeyProvider.getKid() : "n/a");
        }
        if (expectedIssuer != null && !expectedIssuer.isEmpty()) {
            log.info("JWT verification: issuer pinned to '{}'", expectedIssuer);
        } else {
            log.warn("JWT verification: no issuer requirement configured "
                    + "(set app.security.jwt.issuer=https://api.fivucsas.com in prod)");
        }
        if (expectedAudience != null && !expectedAudience.isEmpty()) {
            log.info("JWT verification: audience pinned to '{}'", expectedAudience);
        } else {
            log.warn("JWT verification: no audience requirement configured "
                    + "(set app.security.jwt.audience=fivucsas-api in prod)");
        }

        // Parse revoked-kids CSV once at startup.
        if (revokedKidsCsv != null && !revokedKidsCsv.isBlank()) {
            this.revokedKids = Arrays.stream(revokedKidsCsv.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toCollection(HashSet::new));
            log.warn("JWT verification: explicit kid revocation list = {}", revokedKids);
        } else {
            this.revokedKids = Collections.emptySet();
        }
    }

    @PostConstruct
    void assertProdAlgoIsRs256() {
        if (environment == null) {
            return;
        }
        boolean prodActive = false;
        for (String p : environment.getActiveProfiles()) {
            if ("prod".equals(p)) {
                prodActive = true;
                break;
            }
        }
        if (!prodActive) {
            return;
        }
        String alg = defaultAlgo == null ? "HS512" : defaultAlgo.trim().toUpperCase();
        if (!"RS256".equals(alg)) {
            String msg = String.format(
                    "CRITICAL SECURITY ERROR: prod profile is active but " +
                            "fivucsas.jwt.default-algo=%s. Production MUST sign with RS256. " +
                            "Check application-prod.yml and the JWT_DEFAULT_ALGO env var.",
                    alg);
            log.error(msg);
            throw new IllegalStateException(msg);
        }
        log.info("JWT signing algo locked to RS256 (prod profile)");
    }

    /**
     * SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §aud-claim — prod must pin
     * {@code app.security.jwt.audience}. Fail-fast at boot so a misconfigured
     * deploy can't silently mint tokens with no audience binding (a known
     * forge surface when the same RSA private key is reused across
     * deployments). Mirrors the {@link #assertProdAlgoIsRs256} contract.
     */
    @PostConstruct
    void assertProdAudienceIsConfigured() {
        if (environment == null) {
            return;
        }
        boolean prodActive = false;
        for (String p : environment.getActiveProfiles()) {
            if ("prod".equals(p)) {
                prodActive = true;
                break;
            }
        }
        if (!prodActive) {
            return;
        }
        if (expectedAudience == null || expectedAudience.isBlank()) {
            String msg = "CRITICAL SECURITY ERROR: prod profile is active but "
                    + "app.security.jwt.audience is blank. Production MUST bind an "
                    + "audience claim on every minted token. Check application-prod.yml "
                    + "and the APP_SECURITY_JWT_AUDIENCE env var.";
            log.error(msg);
            throw new IllegalStateException(msg);
        }
        log.info("JWT audience binding locked to '{}' (prod profile)", expectedAudience);
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    @Override
    public String generateAccessToken(String email) {
        return buildToken(new HashMap<>(), email, jwtExpiration);
    }

    @Override
    public String generateAccessToken(String email, java.util.List<String> amr) {
        Map<String, Object> claims = new HashMap<>();
        if (amr != null && !amr.isEmpty()) {
            claims.put("amr", amr);
        }
        return buildToken(claims, email, jwtExpiration);
    }

    public String generateToken(Map<String, Object> extraClaims, String email) {
        return buildToken(extraClaims, email, jwtExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            String email,
            long expiration
    ) {
        var builder = Jwts
                .builder()
                .claims(extraClaims)
                .id(UUID.randomUUID().toString())
                .subject(email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration));

        // §P0-3 / P1-5: stamp the issuer claim on every minted access token so
        // the verification side can reject tokens forged for a different
        // deployment (e.g. a staging RSA key mistakenly reused in dev).
        if (expectedIssuer != null && !expectedIssuer.isEmpty()) {
            builder = builder.issuer(expectedIssuer);
        }

        // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §aud-claim — bind the
        // audience claim (RFC 7519 §4.1.3) so the verification side can reject
        // tokens minted for a different deployment. Missed three times
        // (2026-04-20, 2026-05-02, 2026-05-12) before this commit — see the
        // companion unit test JwtServiceAudienceTest to keep it from
        // disappearing again.
        if (expectedAudience != null && !expectedAudience.isEmpty()) {
            builder = builder.audience().add(expectedAudience).and();
        }

        String alg = defaultAlgo == null ? "HS512" : defaultAlgo.trim().toUpperCase();
        String token;
        if ("RS256".equals(alg)) {
            token = builder
                    .header().keyId(rsaKeyProvider.getKid()).and()
                    .signWith(rsaKeyProvider.getPrivateKey(), Jwts.SIG.RS256)
                    .compact();
        } else {
            // Stamp the active kid from the registry so verifiers route to the
            // matching SecretKey. During parallel-verify rotation this is the
            // newly-rolled kid; tokens signed before rotation keep their old
            // kid and verify against the retired entry.
            token = builder
                    .header().keyId(hsKeyRegistry.getActiveKid()).and()
                    .signWith(hsKeyRegistry.getActiveKey(), Jwts.SIG.HS512)
                    .compact();
        }
        // SECURITY: Never log the actual token - it's a bearer credential
        log.debug("Generated JWT token for user: {} (alg={})", email, alg);
        return token;
    }

    public boolean isTokenValid(String token, String email) {
        final String tokenEmail = extractEmail(token);
        return (tokenEmail.equals(email)) && !isTokenExpired(token);
    }

    @Override
    public long getExpirationMillis() {
        return jwtExpiration;
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        var parserBuilder = Jwts
                .parser()
                .keyLocator(keyLocator());
        // §P0-3 / P1-5: require issuer when configured. Empty config (dev
        // profile) leaves it unrestricted, matching pre-existing behaviour
        // for local-only flows.
        if (expectedIssuer != null && !expectedIssuer.isEmpty()) {
            parserBuilder = parserBuilder.requireIssuer(expectedIssuer);
        }
        // SECURITY_REVIEW / BACKEND_REVIEW 2026-05-12 §aud-claim — when the
        // audience is configured we require the token's `aud` to contain it.
        // JJWT's requireAudience asserts membership in the audience SET so a
        // multi-audience token (future-compat) still verifies as long as our
        // configured audience is one of its entries.
        if (expectedAudience != null && !expectedAudience.isEmpty()) {
            parserBuilder = parserBuilder.requireAudience(expectedAudience);
        }
        Claims claims = parserBuilder
                .build()
                .parseSignedClaims(token)
                .getPayload();

        // SECURITY_REVIEW 2026-05-12 §P1 — defence-in-depth: even when the alg
        // is RS256 (i.e. the HS leaked-kid branch is unreachable in normal
        // ops), refuse any token whose `kid` is on the explicit revocation
        // list. Captures the f8ee668:.env.gcp `hs-2026-04` exposure in a
        // single place that survives future allow-hs512 toggles.
        if (!revokedKids.isEmpty()) {
            // The kid lives in the JWS header; we can't read it off Claims
            // directly, so re-parse the compact form's header segment. Cheap:
            // it's just a base64 decode of the first dot-separated chunk.
            String kid = peekKidUnsafely(token);
            if (kid != null && revokedKids.contains(kid)) {
                throw new io.jsonwebtoken.security.SignatureException(
                        "Rejected revoked JWT kid: " + kid);
            }
        }
        return claims;
    }

    /**
     * Extract the {@code kid} header from a compact JWS without verifying the
     * signature. We've already verified the token by the time this is called
     * (it's on the post-parse path), so this is only used as a final
     * defence-in-depth check against revoked kids.
     */
    private static String peekKidUnsafely(String compactJws) {
        try {
            int dot = compactJws.indexOf('.');
            if (dot <= 0) return null;
            String headerJson = new String(
                    java.util.Base64.getUrlDecoder().decode(compactJws.substring(0, dot)),
                    java.nio.charset.StandardCharsets.UTF_8);
            // Crude but dependency-free: find "kid":"..."
            int idx = headerJson.indexOf("\"kid\"");
            if (idx < 0) return null;
            int colon = headerJson.indexOf(':', idx);
            if (colon < 0) return null;
            int q1 = headerJson.indexOf('"', colon + 1);
            if (q1 < 0) return null;
            int q2 = headerJson.indexOf('"', q1 + 1);
            if (q2 < 0) return null;
            return headerJson.substring(q1 + 1, q2);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Locates the verification key by the JWS {@code kid} header.
     * <ul>
     *   <li>kid in {@link HsKeyRegistry} (active or retired) -> the matching HS512 secret</li>
     *   <li>kid absent (legacy pre-BE-H1 tokens) -> active HS512 secret</li>
     *   <li>kid == {@link RsaKeyProvider#getKid()} -> RS256 public key</li>
     *   <li>anything else -> {@link io.jsonwebtoken.security.SignatureException}</li>
     * </ul>
     * The HS path is gated by {@code app.security.jwt.allow-hs512}.
     */
    private Locator<Key> keyLocator() {
        return new Locator<>() {
            @Override
            public Key locate(io.jsonwebtoken.Header header) {
                if (!(header instanceof JwsHeader jws)) {
                    // Non-JWS header (e.g. unsigned JWT) — refuse outright.
                    throw new io.jsonwebtoken.security.SignatureException(
                            "Unsigned JWT rejected (JWS header required)");
                }
                String kid = jws.getKeyId();
                String alg = jws.getAlgorithm();

                // §P0-3 code half: HS512 verification surface is OFF by
                // default. The leaked f8ee668:.env.gcp HS secret means any
                // HS512-tagged token must be rejected unless the operator
                // explicitly opts in for a rollback window.
                if (kid == null) {
                    // Legacy tokens (pre-BE-H1) had no kid; they were HS512.
                    // Same gate applies — verify against the registry's active key.
                    if (!allowHs512) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "HS512 verification disabled (kid absent); "
                                        + "set app.security.jwt.allow-hs512=true to re-enable");
                    }
                    if (!"HS512".equals(alg)) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "alg/kid mismatch: kid=null requires alg=HS512, got " + alg);
                    }
                    return hsKeyRegistry.getActiveKey();
                }
                if (rsaKeyProvider.getKid().equals(kid)) {
                    if (!"RS256".equals(alg)) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "alg/kid mismatch: kid=" + kid + " requires alg=RS256, got " + alg);
                    }
                    return rsaKeyProvider.getPublicKey();
                }
                // HS512 path: registry lookup. Both the active kid and any
                // retired kids resolve here — that's the parallel-verify
                // window during a key rotation.
                SecretKey hsKey = hsKeyRegistry.keyFor(kid);
                if (hsKey != null) {
                    if (!allowHs512) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "HS512 verification disabled (kid=" + kid + "); "
                                        + "set app.security.jwt.allow-hs512=true to re-enable");
                    }
                    // §P2-3: bind alg-to-kid. JJWT will catch most key/alg
                    // mismatches at signature-verify time, but the explicit
                    // contract closes CVE-2018-0114-shape forgeries where a
                    // header pretends to be one alg while actually using
                    // another.
                    if (!"HS512".equals(alg)) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "alg/kid mismatch: kid=" + kid + " requires alg=HS512, got " + alg);
                    }
                    return hsKey;
                }
                throw new io.jsonwebtoken.security.SignatureException(
                        "Unknown JWT key id: " + kid + " (alg=" + alg + ")");
            }
        };
    }
}
