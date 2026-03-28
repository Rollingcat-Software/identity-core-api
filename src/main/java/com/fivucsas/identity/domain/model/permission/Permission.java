package com.fivucsas.identity.domain.model.permission;

import java.util.Objects;
import java.util.UUID;

/**
 * Pure domain model for Permission.
 * Represents a specific action that can be performed on a resource.
 * Format: RESOURCE:ACTION (e.g., USER:READ, TENANT:MANAGE)
 *
 * No JPA annotations - this is a pure domain concept.
 */
public final class Permission {

    private final UUID id;
    private final String name;
    private final String description;
    private final String resource;
    private final String action;

    private Permission(UUID id, String name, String description, String resource, String action) {
        this.id = id;
        this.name = Objects.requireNonNull(name, "Permission name cannot be null");
        this.description = description;
        this.resource = Objects.requireNonNull(resource, "Resource cannot be null");
        this.action = Objects.requireNonNull(action, "Action cannot be null");
    }

    // ========== Factory Methods ==========

    /**
     * Creates a permission with all fields.
     */
    public static Permission of(UUID id, String name, String description, String resource, String action) {
        return new Permission(id, name, description, resource, action);
    }

    /**
     * Creates a new permission from resource and action.
     */
    public static Permission create(String resource, String action, String description) {
        String name = resource.toUpperCase() + ":" + action.toUpperCase();
        return new Permission(null, name, description, resource.toUpperCase(), action.toUpperCase());
    }

    /**
     * Reconstitutes a permission from persistence.
     */
    public static Permission reconstitute(UUID id, String name, String description,
                                          String resource, String action) {
        return new Permission(id, name, description, resource, action);
    }

    // ========== Business Methods ==========

    /**
     * Gets the full permission string (RESOURCE:ACTION).
     */
    public String getPermissionString() {
        return resource + ":" + action;
    }

    /**
     * Returns the authority name in Spring Security format (lowercase).
     */
    public String getAuthorityName() {
        return resource.toLowerCase() + ":" + action.toLowerCase();
    }

    // ========== Getters ==========

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getResource() {
        return resource;
    }

    public String getAction() {
        return action;
    }

    // ========== Equality ==========

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Permission that)) return false;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public String toString() {
        return "Permission{id=" + id + ", name='" + name + "', resource='" + resource +
               "', action='" + action + "'}";
    }
}
