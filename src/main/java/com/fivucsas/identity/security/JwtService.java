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
     * AUDIT_2026-04-30 P1.6 — RFC 7519 §4.1.1 issuer claim. Every JWT minted by
     * this service stamps {@code iss}; every JWT parsed by this service must
     * present a matching {@code iss} or it is rejected. Defaulted in
     * application.yml; profile-specific overrides via {@code JWT_ISSUER}.
     */
    @Value("${jwt.issuer:https://api.fivucsas.com}")
    private String issuer;

    /**
     * AUDIT_2026-04-30 P1.6 — RFC 7519 §4.1.3 audience claim. Same contract as
     * {@link #issuer}: stamped on mint, required on parse. Override via
     * {@code JWT_AUDIENCE}.
     */
    @Value("${jwt.audience:fivucsas-api}")
    private String audience;

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
        // P1.6: stamp iss/aud BEFORE the (possibly-empty) claims map, otherwise
        // a caller passing claims that include reserved names would clobber
        // them. JJWT's builder applies setters in fluent order; iss/aud last
        // win, so set them explicitly after .claims().
        var builder = Jwts
                .builder()
                .claims(extraClaims)
                .id(UUID.randomUUID().toString())
                .subject(email)
                .issuer(issuer)
                .audience().add(audience).and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration));

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
        // P1.6: requireIssuer/requireAudience apply to BOTH the RS256 path and
        // the HS512 null-kid backward-compat fallback inside keyLocator().
        // Tokens missing/mismatched on either claim throw
        // IncorrectClaimException or MissingClaimException (both extend
        // JwtException) — our SecurityFilter already catches JwtException and
        // returns 401, so no extra catch chain is required here.
        return Jwts
                .parser()
                .keyLocator(keyLocator())
                .requireIssuer(issuer)
                .requireAudience(audience)
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
                    return getHmacSignInKey();
                }
                String kid = jws.getKeyId();
                String alg = jws.getAlgorithm();
                if (kid == null) {
                    // Legacy tokens minted before BE-H1: no kid, HS512 only.
                    return getHmacSignInKey();
                }
                if (HS_KID.equals(kid)) {
                    return getHmacSignInKey();
                }
                if (rsaKeyProvider.getKid().equals(kid)) {
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
