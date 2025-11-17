package com.fivucsas.identity.application.port.output;

/**
 * Output port for password encoding operations.
 *
 * This interface defines the contract for password hashing and verification.
 * The application layer defines what it needs, and the infrastructure
 * layer provides the implementation (BCryptPasswordEncoder).
 *
 * Following principles:
 * - Dependency Inversion: Application defines the port, infrastructure implements
 * - Interface Segregation: Only password encoding
 * - Security: Abstracts password hashing algorithm details
 */
public interface PasswordEncoderPort {

    /**
     * Encodes (hashes) a plain text password.
     *
     * @param plainPassword the plain text password
     * @return the hashed password (BCrypt format)
     */
    String encode(String plainPassword);

    /**
     * Checks if a plain text password matches a hashed password.
     *
     * @param plainPassword the plain text password
     * @param hashedPassword the hashed password
     * @return true if passwords match
     */
    boolean matches(String plainPassword, String hashedPassword);
}
