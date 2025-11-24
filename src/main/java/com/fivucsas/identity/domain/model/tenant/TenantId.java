package com.fivucsas.identity.domain.model.tenant;

import java.util.Objects;
import java.util.UUID;

/**
 * Value Object representing a Tenant's unique identifier.
 * Immutable wrapper around UUID.
 *
 * Following principles:
 * - Type Safety: Prevents mixing up different ID types
 * - Immutability: Thread-safe
 * - Encapsulation: Hides UUID implementation details
 */
public final class TenantId {

    private final UUID value;

    private TenantId(UUID value) {
        this.value = Objects.requireNonNull(value, "TenantId cannot be null");
    }

    /**
     * Creates a new random TenantId.
     */
    public static TenantId generate() {
        return new TenantId(UUID.randomUUID());
    }

    /**
     * Creates TenantId from existing UUID.
     */
    public static TenantId of(UUID uuid) {
        return new TenantId(uuid);
    }

    /**
     * Creates TenantId from string representation.
     *
     * @throws IllegalArgumentException if string is not a valid UUID
     */
    public static TenantId of(String uuidString) {
        try {
            return new TenantId(UUID.fromString(uuidString));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid TenantId format: " + uuidString, e);
        }
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TenantId tenantId = (TenantId) o;
        return Objects.equals(value, tenantId.value);
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
