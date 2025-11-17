package com.fivucsas.identity.domain.model.user;

import java.util.Objects;
import java.util.UUID;

/**
 * Value Object representing a User's unique identifier.
 * Immutable wrapper around UUID.
 *
 * Following principles:
 * - Type Safety: Prevents mixing up different ID types
 * - Immutability: Thread-safe
 * - Encapsulation: Hides UUID implementation details
 */
public final class UserId {

    private final UUID value;

    private UserId(UUID value) {
        this.value = Objects.requireNonNull(value, "UserId cannot be null");
    }

    /**
     * Creates a new random UserId.
     */
    public static UserId generate() {
        return new UserId(UUID.randomUUID());
    }

    /**
     * Creates UserId from existing UUID.
     */
    public static UserId of(UUID uuid) {
        return new UserId(uuid);
    }

    /**
     * Creates UserId from string representation.
     *
     * @throws IllegalArgumentException if string is not a valid UUID
     */
    public static UserId of(String uuidString) {
        try {
            return new UserId(UUID.fromString(uuidString));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid UserId format: " + uuidString, e);
        }
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserId userId = (UserId) o;
        return Objects.equals(value, userId.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
