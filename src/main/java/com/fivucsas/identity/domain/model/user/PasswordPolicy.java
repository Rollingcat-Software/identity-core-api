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
     * <p>On failure throws {@link com.fivucsas.identity.domain.exception.PasswordPolicyViolationException}
     * carrying a list of locale-independent violation keys (e.g.
     * {@code MIN_LENGTH}, {@code REQUIRE_UPPERCASE}). The frontend renders
     * the user-facing copy via i18n — see
     * INVESTIGATION_MASTER_2026-05-07 §"user constraints".
     *
     * @param password the password to validate
     * @throws com.fivucsas.identity.domain.exception.PasswordPolicyViolationException
     *         if password violates any rule
     */
    public static void validate(String password) {
        List<String> violationKeys = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            // Empty password is its own dedicated key — distinct from
            // length-too-short so the i18n copy can be more specific.
            throw new com.fivucsas.identity.domain.exception.PasswordPolicyViolationException(
                    List.of("EMPTY"));
        }

        if (password.length() < MIN_LENGTH) {
            violationKeys.add("MIN_LENGTH");
        }

        if (password.length() > MAX_LENGTH) {
            violationKeys.add("MAX_LENGTH");
        }

        if (!UPPERCASE_PATTERN.matcher(password).find()) {
            violationKeys.add("REQUIRE_UPPERCASE");
        }

        if (!LOWERCASE_PATTERN.matcher(password).find()) {
            violationKeys.add("REQUIRE_LOWERCASE");
        }

        if (!DIGIT_PATTERN.matcher(password).find()) {
            violationKeys.add("REQUIRE_DIGIT");
        }

        if (!SPECIAL_CHAR_PATTERN.matcher(password).find()) {
            violationKeys.add("REQUIRE_SPECIAL_CHAR");
        }

        if (!violationKeys.isEmpty()) {
            throw new com.fivucsas.identity.domain.exception.PasswordPolicyViolationException(violationKeys);
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
        } catch (com.fivucsas.identity.domain.exception.PasswordPolicyViolationException e) {
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
