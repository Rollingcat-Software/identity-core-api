package com.fivucsas.identity.domain.model.user;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value Object representing an email address.
 * Immutable and self-validating.
 *
 * Following principles:
 * - Single Responsibility: Validates and represents email
 * - Immutability: Thread-safe, no setters
 * - Type Safety: Prevents invalid emails at compile time
 */
public final class Email {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final int MAX_LENGTH = 255;

    private final String value;

    private Email(String value) {
        this.value = value;
    }

    /**
     * Factory method to create Email from string.
     * Validates the email format.
     *
     * @param email the email string
     * @return Email value object
     * @throws IllegalArgumentException if email is invalid
     */
    public static Email of(String email) {
        validate(email);
        return new Email(email.toLowerCase().trim());
    }

    private static void validate(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email cannot be null or empty");
        }

        String trimmed = email.trim();

        if (trimmed.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                String.format("Email cannot exceed %d characters", MAX_LENGTH)
            );
        }

        if (!EMAIL_PATTERN.matcher(trimmed).matches()) {
            throw new IllegalArgumentException("Invalid email format");
        }
    }

    public String getValue() {
        return value;
    }

    /**
     * Returns the local part of the email (before @).
     */
    public String getLocalPart() {
        return value.substring(0, value.indexOf('@'));
    }

    /**
     * Returns the domain part of the email (after @).
     */
    public String getDomain() {
        return value.substring(value.indexOf('@') + 1);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Email email = (Email) o;
        return Objects.equals(value, email.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
