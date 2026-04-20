package com.fivucsas.identity.security;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
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

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${fivucsas.jwt.default-algo:HS512}")
    private String defaultAlgo;

    public JwtService(JwtSecretProvider jwtSecretProvider, RsaKeyProvider rsaKeyProvider) {
        this.jwtSecretProvider = jwtSecretProvider;
        this.rsaKeyProvider = rsaKeyProvider;
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
        return Jwts
                .parser()
                .keyLocator(keyLocator())
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
