package com.fivucsas.identity.security;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

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

    public static final String HS_KID = "hs-2026-04";

    private final JwtSecretProvider jwtSecretProvider;
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

    public JwtService(JwtSecretProvider jwtSecretProvider,
                      RsaKeyProvider rsaKeyProvider,
                      Environment environment) {
        this.jwtSecretProvider = jwtSecretProvider;
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

        String alg = defaultAlgo == null ? "HS512" : defaultAlgo.trim().toUpperCase();
        String token;
        if ("RS256".equals(alg)) {
            token = builder
                    .header().keyId(rsaKeyProvider.getKid()).and()
                    .signWith(rsaKeyProvider.getPrivateKey(), Jwts.SIG.RS256)
                    .compact();
        } else {
            token = builder
                    .header().keyId(HS_KID).and()
                    .signWith(getHmacSignInKey(), Jwts.SIG.HS512)
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
        return parserBuilder
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Locates the verification key by the JWS {@code kid} header.
     * - "hs-2026-04" (or null kid for backward compatibility with legacy tokens) -> HS512 secret
     * - the RSA kid -> RS256 public key
     * Any other kid is rejected.
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
                    // Same gate applies.
                    if (!allowHs512) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "HS512 verification disabled (kid absent); "
                                        + "set app.security.jwt.allow-hs512=true to re-enable");
                    }
                    if (!"HS512".equals(alg)) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "alg/kid mismatch: kid=null requires alg=HS512, got " + alg);
                    }
                    return getHmacSignInKey();
                }
                if (HS_KID.equals(kid)) {
                    if (!allowHs512) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "HS512 verification disabled (kid=" + HS_KID + "); "
                                        + "set app.security.jwt.allow-hs512=true to re-enable");
                    }
                    // §P2-3: bind alg-to-kid. JJWT will catch most key/alg
                    // mismatches at signature-verify time, but the explicit
                    // contract closes CVE-2018-0114-shape forgeries where a
                    // header pretends to be one alg while actually using
                    // another.
                    if (!"HS512".equals(alg)) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "alg/kid mismatch: kid=" + HS_KID + " requires alg=HS512, got " + alg);
                    }
                    return getHmacSignInKey();
                }
                if (rsaKeyProvider.getKid().equals(kid)) {
                    if (!"RS256".equals(alg)) {
                        throw new io.jsonwebtoken.security.SignatureException(
                                "alg/kid mismatch: kid=" + kid + " requires alg=RS256, got " + alg);
                    }
                    return rsaKeyProvider.getPublicKey();
                }
                throw new io.jsonwebtoken.security.SignatureException(
                        "Unknown JWT key id: " + kid + " (alg=" + alg + ")");
            }
        };
    }

    private SecretKey getHmacSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecretProvider.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
