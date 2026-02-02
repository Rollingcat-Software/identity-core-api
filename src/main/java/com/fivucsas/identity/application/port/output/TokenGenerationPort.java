package com.fivucsas.identity.application.port.output;

/**
 * Output port for JWT token generation.
 *
 * This interface defines the contract for token generation operations.
 * The application layer defines what it needs, and the infrastructure
 * layer provides the implementation (JwtService).
 *
 * Following principles:
 * - Dependency Inversion: Application defines the port, infrastructure implements
 * - Interface Segregation: Only token generation
 * - Security: Handles sensitive token operations
 */
public interface TokenGenerationPort {

    /**
     * Generates a JWT access token for the given email.
     *
     * @param email the user email
     * @return JWT access token string
     */
    String generateAccessToken(String email);

    /**
     * Extracts the email from a JWT token.
     *
     * @param token the JWT token
     * @return the email extracted from the token
     */
    String extractEmail(String token);

    /**
     * Validates a JWT token.
     *
     * @param token the JWT token
     * @param email the expected email
     * @return true if token is valid
     */
    boolean isTokenValid(String token, String email);

    /**
     * Returns the configured JWT expiration time in milliseconds.
     *
     * @return expiration time in milliseconds
     */
    long getExpirationMillis();
}
