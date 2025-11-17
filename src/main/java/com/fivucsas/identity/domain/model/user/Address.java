package com.fivucsas.identity.domain.model.user;

import java.util.Objects;

/**
 * Value Object representing a physical address.
 * Immutable and self-validating.
 *
 * Simplified version - can be extended to include:
 * - Street, City, State, Country, PostalCode as separate fields
 * - Address validation against postal services
 * - Geocoding integration
 */
public final class Address {

    private static final int MAX_LENGTH = 500;
    private static final int MIN_LENGTH = 5;

    private final String value;

    private Address(String value) {
        this.value = value;
    }

    /**
     * Factory method to create Address from string.
     *
     * @param address the address string
     * @return Address value object
     * @throws IllegalArgumentException if address is invalid
     */
    public static Address of(String address) {
        validate(address);
        return new Address(address.trim());
    }

    /**
     * Creates optional Address, returns null if input is null/empty.
     */
    public static Address ofNullable(String address) {
        if (address == null || address.trim().isEmpty()) {
            return null;
        }
        return of(address);
    }

    private static void validate(String address) {
        if (address == null || address.trim().isEmpty()) {
            throw new IllegalArgumentException("Address cannot be null or empty");
        }

        String trimmed = address.trim();

        if (trimmed.length() < MIN_LENGTH) {
            throw new IllegalArgumentException(
                String.format("Address must be at least %d characters", MIN_LENGTH)
            );
        }

        if (trimmed.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                String.format("Address cannot exceed %d characters", MAX_LENGTH)
            );
        }
    }

    public String getValue() {
        return value;
    }

    /**
     * Returns a shortened version of the address (first 50 characters).
     */
    public String getShortForm() {
        if (value.length() <= 50) {
            return value;
        }
        return value.substring(0, 47) + "...";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Address address = (Address) o;
        return Objects.equals(value, address.value);
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
