package com.fivucsas.identity.util;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Utility test to generate BCrypt hashes for seed data.
 */
class BcryptHashGenerator {

    @Test
    void generateHashes() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        String adminPassword = "Admin123!";
        String userPassword = "User123!";

        String adminHash = encoder.encode(adminPassword);
        String userHash = encoder.encode(userPassword);

        System.out.println("=== BCrypt Hashes ===");
        System.out.println("Admin123! => " + adminHash);
        System.out.println("User123!  => " + userHash);
        System.out.println("=====================");

        // Verify hashes work
        assert encoder.matches(adminPassword, adminHash) : "Admin hash verification failed";
        assert encoder.matches(userPassword, userHash) : "User hash verification failed";

        System.out.println("Both hashes verified successfully!");
    }
}
