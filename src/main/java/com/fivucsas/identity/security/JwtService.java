package com.fivucsas.identity.security;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
@Primary
public class JwtService implements TokenGenerationPort {

    private final JwtSecretProvider jwtSecretProvider;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    public JwtService(JwtSecretProvider jwtSecretProvider) {
        this.jwtSecretProvider = jwtSecretProvider;
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

    public String generateToken(Map<String, Object> extraClaims, String email) {
        return buildToken(extraClaims, email, jwtExpiration);
    }

    public String generateStepUpToken(String email, String userId, long expirationMillis) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("amr", List.of("biometric"));
        claims.put("uid", userId);
        claims.put("type", "step_up");
        return buildToken(claims, email, expirationMillis);
    }

    public String extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("uid", String.class));
    }

    public boolean isStepUpTokenValid(String token, String email) {
        final Claims claims = extractAllClaims(token);
        final String tokenEmail = claims.getSubject();
        final String type = claims.get("type", String.class);
        return email.equals(tokenEmail)
                && "step_up".equals(type)
                && hasBiometricAmr(claims)
                && !claims.getExpiration().before(new Date());
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            String email,
            long expiration
    ) {
        String token = Jwts
                .builder()
                .claims(extraClaims)
                .subject(email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
        // SECURITY: Never log the actual token - it's a bearer credential
        log.debug("Generated JWT token for user: {}", email);
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

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean hasBiometricAmr(Claims claims) {
        Object amr = claims.get("amr");
        if (amr instanceof Collection<?> collection) {
            return collection.stream().anyMatch(value -> "biometric".equals(String.valueOf(value)));
        }
        if (amr instanceof String amrString) {
            return "biometric".equals(amrString);
        }
        return false;
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecretProvider.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
