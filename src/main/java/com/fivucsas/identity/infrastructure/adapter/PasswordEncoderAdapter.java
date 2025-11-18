package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.port.output.PasswordEncoderPort;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Infrastructure adapter for password encoding.
 *
 * Implements the PasswordEncoderPort using Spring Security's PasswordEncoder.
 * This adapter bridges the application layer with the infrastructure.
 *
 * Following principles:
 * - Adapter Pattern: Adapts Spring's PasswordEncoder to our port
 * - Dependency Inversion: Application defines port, infrastructure implements
 */
@Component
@RequiredArgsConstructor
public class PasswordEncoderAdapter implements PasswordEncoderPort {

    private final PasswordEncoder passwordEncoder;

    @Override
    public String encode(String plainPassword) {
        return passwordEncoder.encode(plainPassword);
    }

    @Override
    public boolean matches(String plainPassword, String hashedPassword) {
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
}
