package com.fivucsas.identity.domain.model.user;

import java.util.Objects;

/**
 * Value Object representing a national ID number.
 * Immutable and self-validating.
 *
 * Currently supports Turkish ID numbers (11 digits).
 * Can be extended to support multiple countries with different formats.
 *
 * Following principles:
 * - Single Responsibility: Validates and represents ID numbers
 * - Open/Closed: Can be extended for other country formats
 * - Type Safety: Prevents invalid ID numbers
 */
public final class IdNumber {

    private static final int TURKISH_ID_LENGTH = 11;

    private final String value;

    private IdNumber(String value) {
        this.value = value;
    }

    /**
     * Factory method to create IdNumber from string.
     * Currently validates Turkish ID number format (11 digits).
     *
     * @param idNumber the ID number string
     * @return IdNumber value object
     * @throws IllegalArgumentException if ID number is invalid
     */
    public static IdNumber of(String idNumber) {
        validate(idNumber);
        return new IdNumber(idNumber.trim());
    }

    /**
     * Creates optional IdNumber, returns null if input is null/empty.
     */
    public static IdNumber ofNullable(String idNumber) {
        if (idNumber == null || idNumber.trim().isEmpty()) {
            return null;
        }
        return of(idNumber);
    }

    private static void validate(String idNumber) {
        if (idNumber == null || idNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("ID number cannot be null or empty");
        }

        String trimmed = idNumber.trim();

        // Validate Turkish ID number format
        if (!trimmed.matches("\\d{11}")) {
            throw new IllegalArgumentException(
                "Invalid ID number format. Expected 11 digits for Turkish ID."
            );
        }

        if (trimmed.charAt(0) == '0') {
            throw new IllegalArgumentException("ID number cannot start with 0");
        }

        // // Validate Turkish ID checksum algorithm
        // if (!isValidTurkishId(trimmed)) {
        //     throw new IllegalArgumentException("Invalid Turkish ID number checksum");
        // }
    }

    /**
     * Validates Turkish ID number using the official checksum algorithm.
     * See: https://en.wikipedia.org/wiki/Turkish_Identification_Number
     */
    private static boolean isValidTurkishId(String id) {
        if (id.length() != TURKISH_ID_LENGTH) {
            return false;
        }

        int[] digits = new int[11];
        for (int i = 0; i < 11; i++) {
            digits[i] = Character.getNumericValue(id.charAt(i));
        }

        // Check 10th digit
        int sumOdd = 0;
        int sumEven = 0;
        for (int i = 0; i < 9; i++) {
            if (i % 2 == 0) { // 1st, 3rd, 5th, 7th, 9th digits (indices 0, 2, 4, 6, 8)
                sumOdd += digits[i];
            } else { // 2nd, 4th, 6th, 8th digits (indices 1, 3, 5, 7)
                sumEven += digits[i];
            }
        }
        // Calculate 10th digit (d9)
        int d9 = ( (sumOdd * 7) - (sumEven * 9) ) % 10;
        if (d9 < 0) { // Handle negative modulo result
            d9 += 10;
        }
        if (d9 != digits[9]) {
            return false;
        }

        // Check 11th digit
        int sum11 = 0;
        for (int i = 0; i < 10; i++) {
            sum11 += digits[i];
        }
        return sum11 % 10 == digits[10];
    }

    public String getValue() {
        return value;
    }

    /**
     * Returns masked ID number for display (e.g., "12345***890").
     */
    public String getMasked() {
        if (value.length() != TURKISH_ID_LENGTH) {
            return value;
        }
        return value.substring(0, 5) + "***" + value.substring(8);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IdNumber idNumber = (IdNumber) o;
        return Objects.equals(value, idNumber.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return getMasked(); // Never log full ID number
    }
}
