package com.fivucsas.identity.config;

import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.security.SecurePasswordGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Data initializer for development environment ONLY.
 * Creates a default admin user with a secure random password.
 *
 * SECURITY NOTICE:
 * - This component only runs in 'dev' profile
 * - Password is generated using SecurePasswordGenerator
 * - Password is logged ONCE and MUST be changed on first login
 * - DO NOT use hardcoded passwords
 * - In production, create admin users via secure admin tools
 *
 * @author FIVUCSAS Team
 * @since 1.0.0
 */
@Component
@Profile("dev")  // SECURITY: Only run in development
@Slf4j
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurePasswordGenerator passwordGenerator;

    @Override
    public void run(String... args) {
        log.info("Running development data initializer...");

        if (userRepository.count() == 0) {
            log.info("No users found. Creating default admin user for development...");

            // SECURITY: Generate secure random password instead of hardcoded
            String temporaryPassword = passwordGenerator.generateTemporaryPassword();

            User admin = User.builder()
                .email("admin@fivucsas.com")
                .passwordHash(passwordEncoder.encode(temporaryPassword))
                .firstName("Admin")
                .lastName("User")
                .status(UserStatus.ACTIVE)
                .isBiometricEnrolled(false)
                .verificationCount(0)
                .build();

            userRepository.save(admin);

            // SECURITY: Log password ONCE for development convenience
            // In production, use secure password delivery mechanism
            log.warn("╔════════════════════════════════════════════════════════════════════════╗");
            log.warn("║  DEVELOPMENT ONLY: Default Admin Credentials                          ║");
            log.warn("║  Email: admin@fivucsas.com                                            ║");
            log.warn("║  Password: {}                                         ║", temporaryPassword);
            log.warn("║  IMPORTANT: Change this password immediately after first login!       ║");
            log.warn("║  This message appears only in 'dev' profile.                          ║");
            log.warn("╚════════════════════════════════════════════════════════════════════════╝");

        } else {
            log.info("Database already contains data. No initialization needed.");
        }
    }
}
