package com.fivucsas.identity.domain.model.user;

import java.util.Objects;

/**
 * Value Object representing a hashed password.
 * Immutable and type-safe.
 *
 * IMPORTANT: This represents an ALREADY HASHED password.
 * Plain text passwords should never be stored in this object.
 *
 * Following principles:
 * - Type Safety: Prevents accidental use of plain text passwords
 * - Immutability: Thread-safe
 * - Security: Makes it clear this is hashed, not plain text
 */
public final class HashedPassword {

    private final String value;

    private HashedPassword(String hashedValue) {
        this.value = Objects.requireNonNull(hashedValue, "Hashed password cannot be null");

        if (hashedValue.trim().isEmpty()) {
            throw new IllegalArgumentException("Hashed password cannot be empty");
        }

        // BCrypt hashes are always 60 characters
        if (hashedValue.length() != 60 || !hashedValue.startsWith("$2")) {
            throw new IllegalArgumentException("Invalid BCrypt hash format");
        }
    }

    /**
     * Creates HashedPassword from BCrypt hash string.
     *
     * @param bcryptHash the BCrypt hashed password
     * @return HashedPassword value object
     * @throws IllegalArgumentException if not a valid BCrypt hash
     */
    public static HashedPassword of(String bcryptHash) {
        return new HashedPassword(bcryptHash);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HashedPassword that = (HashedPassword) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "[PROTECTED]"; // Never log actual hash
    }
}
