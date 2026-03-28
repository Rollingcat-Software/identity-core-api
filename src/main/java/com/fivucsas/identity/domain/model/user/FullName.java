package com.fivucsas.identity.domain.model.user;

import java.util.Objects;

/**
 * Value Object representing a person's full name.
 * Immutable and self-validating.
 *
 * Following principles:
 * - Single Responsibility: Manages name validation and formatting
 * - Immutability: Thread-safe
 * - Encapsulation: Hides name composition logic
 */
public final class FullName {

    private static final int MAX_LENGTH = 100;
    private static final int MIN_LENGTH = 1;

    private final String firstName;
    private final String lastName;

    private FullName(String firstName, String lastName) {
        this.firstName = firstName;
        this.lastName = lastName;
    }

    /**
     * Factory method to create FullName.
     *
     * @param firstName the first name
     * @param lastName the last name
     * @return FullName value object
     * @throws IllegalArgumentException if names are invalid
     */
    public static FullName of(String firstName, String lastName) {
        validateName(firstName, "First name");
        validateName(lastName, "Last name");

        return new FullName(
            firstName.trim(),
            lastName.trim()
        );
    }

    private static void validateName(String name, String fieldName) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " cannot be null or empty");
        }

        String trimmed = name.trim();

        if (trimmed.length() < MIN_LENGTH) {
            throw new IllegalArgumentException(
                String.format("%s must be at least %d character", fieldName, MIN_LENGTH)
            );
        }

        if (trimmed.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                String.format("%s cannot exceed %d characters", fieldName, MAX_LENGTH)
            );
        }

        // Allow Unicode letters (supports Turkish, Arabic, etc.), spaces, hyphens, apostrophes
        if (!trimmed.matches("^[\\p{L} ,.'-]+$")) {
            throw new IllegalArgumentException(
                fieldName + " contains invalid characters. Only letters, spaces, hyphens, and apostrophes are allowed."
            );
        }
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    /**
     * Returns the full name as "FirstName LastName".
     */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    /**
     * Returns initials (e.g., "John Doe" -> "JD").
     */
    public String getInitials() {
        return String.valueOf(firstName.charAt(0)) + lastName.charAt(0);
    }

    /**
     * Returns formatted name as "LASTNAME, Firstname".
     */
    public String getFormattedName() {
        return lastName.toUpperCase() + ", " + capitalize(firstName);
    }

    private String capitalize(String str) {
        if (str == null || str.isEmpty()) return str;
        return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FullName fullName = (FullName) o;
        return Objects.equals(firstName, fullName.firstName) &&
               Objects.equals(lastName, fullName.lastName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(firstName, lastName);
    }

    @Override
    public String toString() {
        return getFullName();
    }
}
