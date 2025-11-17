package com.fivucsas.identity.domain.model.user;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value Object representing a phone number.
 * Immutable and self-validating.
 *
 * Supports international format: +[country code][number]
 * Example: +905551234567 (Turkey)
 */
public final class PhoneNumber {

    // International format: + followed by 10-15 digits
    private static final Pattern PHONE_PATTERN = Pattern.compile(
        "^\\+[1-9]\\d{9,14}$"
    );

    private final String value;

    private PhoneNumber(String value) {
        this.value = value;
    }

    /**
     * Factory method to create PhoneNumber from string.
     *
     * @param phoneNumber the phone number in international format (+country_code_number)
     * @return PhoneNumber value object
     * @throws IllegalArgumentException if phone number is invalid
     */
    public static PhoneNumber of(String phoneNumber) {
        validate(phoneNumber);
        return new PhoneNumber(phoneNumber.trim());
    }

    /**
     * Creates optional PhoneNumber, returns null if input is null/empty.
     */
    public static PhoneNumber ofNullable(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.trim().isEmpty()) {
            return null;
        }
        return of(phoneNumber);
    }

    private static void validate(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("Phone number cannot be null or empty");
        }

        String trimmed = phoneNumber.trim();

        if (!PHONE_PATTERN.matcher(trimmed).matches()) {
            throw new IllegalArgumentException(
                "Invalid phone number format. Expected: +[country code][number] (e.g., +905551234567)"
            );
        }
    }

    public String getValue() {
        return value;
    }

    /**
     * Returns the country code (digits after + and before the main number).
     * Example: +905551234567 -> 90
     */
    public String getCountryCode() {
        // Simple heuristic: country codes are 1-3 digits
        String digits = value.substring(1); // Remove +

        // Check common country code lengths
        if (digits.startsWith("1")) return "1"; // USA, Canada
        if (digits.length() >= 2 && (digits.startsWith("90") || digits.startsWith("44") ||
            digits.startsWith("49"))) return digits.substring(0, 2);
        if (digits.length() >= 3) return digits.substring(0, 3);

        return digits.substring(0, Math.min(2, digits.length()));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PhoneNumber that = (PhoneNumber) o;
        return Objects.equals(value, that.value);
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
