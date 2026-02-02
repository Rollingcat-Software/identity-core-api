package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.TokenGenerationPort;
import com.fivucsas.identity.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Infrastructure adapter for JWT token generation.
 *
 * Implements the TokenGenerationPort using our JwtService.
 * This adapter bridges the application layer with the infrastructure.
 *
 * Following principles:
 * - Adapter Pattern: Adapts JwtService to our port
 * - Dependency Inversion: Application defines port, infrastructure implements
 */
@Component
@RequiredArgsConstructor
public class TokenGenerationAdapter implements TokenGenerationPort {

    private final JwtService jwtService;

    @Override
    public String generateAccessToken(String email) {
        return jwtService.generateAccessToken(email);
    }

    @Override
    public String extractEmail(String token) {
        return jwtService.extractEmail(token);
    }

    @Override
    public boolean isTokenValid(String token, String email) {
        return jwtService.isTokenValid(token, email);
    }

    @Override
    public long getExpirationMillis() {
        return jwtService.getExpirationMillis();
    }
}
