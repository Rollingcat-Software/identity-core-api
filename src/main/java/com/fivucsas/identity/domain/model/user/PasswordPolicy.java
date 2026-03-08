package com.fivucsas.identity.domain.model.user;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Password Policy enforcer.
 *
 * Enforces password complexity requirements:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one digit
 * - At least one special character
 *
 * Following principles:
 * - Single Responsibility: Only validates password policy
 * - Domain Logic: Business rule enforcement in domain layer
 */
public class PasswordPolicy {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 128;

    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]");

    /**
     * Validates password against policy rules.
     *
     * @param password the password to validate
     * @throws IllegalArgumentException if password doesn't meet policy
     */
    public static void validate(String password) {
        List<String> violations = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        if (password.length() < MIN_LENGTH) {
            violations.add(String.format("Password must be at least %d characters long", MIN_LENGTH));
        }

        if (password.length() > MAX_LENGTH) {
            violations.add(String.format("Password must not exceed %d characters", MAX_LENGTH));
        }

        if (!UPPERCASE_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one uppercase letter");
        }

        if (!LOWERCASE_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one lowercase letter");
        }

        if (!DIGIT_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one digit");
        }

        if (!SPECIAL_CHAR_PATTERN.matcher(password).find()) {
            violations.add("Password must contain at least one special character (!@#$%^&*...)");
        }

        if (!violations.isEmpty()) {
            throw new IllegalArgumentException("Password does not meet policy requirements: " + String.join("; ", violations));
        }
    }

    /**
     * Checks if password meets policy without throwing exception.
     *
     * @param password the password to check
     * @return true if password is valid
     */
    public static boolean isValid(String password) {
        try {
            validate(password);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Returns list of policy requirements as strings.
     *
     * @return list of requirements
     */
    public static List<String> getRequirements() {
        return List.of(
            "At least " + MIN_LENGTH + " characters long",
            "At least one uppercase letter (A-Z)",
            "At least one lowercase letter (a-z)",
            "At least one digit (0-9)",
            "At least one special character (!@#$%^&*...)",
            "Maximum " + MAX_LENGTH + " characters"
        );
    }
}
