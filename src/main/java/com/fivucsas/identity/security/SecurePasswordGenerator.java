package com.fivucsas.identity.security;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Secure password generator that creates cryptographically strong passwords.
 *
 * Password Requirements (OWASP Compliant):
 * - Minimum 12 characters
 * - At least 1 uppercase letter
 * - At least 1 lowercase letter
 * - At least 1 digit
 * - At least 1 special character
 * - Uses SecureRandom for cryptographic strength
 *
 * @author FIVUCSAS Team
 * @since 1.0.0
 */
@Component
public class SecurePasswordGenerator {

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    private static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARS;

    private static final int DEFAULT_PASSWORD_LENGTH = 16;
    private static final int MINIMUM_PASSWORD_LENGTH = 12;

    private final SecureRandom secureRandom;

    public SecurePasswordGenerator() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a secure random password with default length (16 characters).
     *
     * @return cryptographically strong password
     */
    public String generatePassword() {
        return generatePassword(DEFAULT_PASSWORD_LENGTH);
    }

    /**
     * Generates a secure random password with specified length.
     *
     * @param length desired password length (minimum 12)
     * @return cryptographically strong password
     * @throws IllegalArgumentException if length < 12
     */
    public String generatePassword(int length) {
        if (length < MINIMUM_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                String.format("Password length must be at least %d characters", MINIMUM_PASSWORD_LENGTH)
            );
        }

        List<Character> passwordChars = new ArrayList<>();

        // Ensure at least one character from each required category
        passwordChars.add(UPPERCASE.charAt(secureRandom.nextInt(UPPERCASE.length())));
        passwordChars.add(LOWERCASE.charAt(secureRandom.nextInt(LOWERCASE.length())));
        passwordChars.add(DIGITS.charAt(secureRandom.nextInt(DIGITS.length())));
        passwordChars.add(SPECIAL_CHARS.charAt(secureRandom.nextInt(SPECIAL_CHARS.length())));

        // Fill the rest with random characters from all categories
        for (int i = passwordChars.size(); i < length; i++) {
            passwordChars.add(ALL_CHARS.charAt(secureRandom.nextInt(ALL_CHARS.length())));
        }

        // Shuffle to avoid predictable patterns
        Collections.shuffle(passwordChars, secureRandom);

        // Convert to string
        StringBuilder password = new StringBuilder(length);
        for (Character ch : passwordChars) {
            password.append(ch);
        }

        return password.toString();
    }

    /**
     * Validates if a password meets security requirements.
     *
     * @param password the password to validate
     * @return true if password meets all requirements
     */
    public boolean isPasswordSecure(String password) {
        if (password == null || password.length() < MINIMUM_PASSWORD_LENGTH) {
            return false;
        }

        boolean hasUppercase = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLowercase = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch ->
            SPECIAL_CHARS.indexOf(ch) >= 0
        );

        return hasUppercase && hasLowercase && hasDigit && hasSpecial;
    }

    /**
     * Generates a temporary password for initial user creation.
     * This password should be changed on first login.
     *
     * @return secure temporary password
     */
    public String generateTemporaryPassword() {
        return generatePassword(DEFAULT_PASSWORD_LENGTH);
    }
}
