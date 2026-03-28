package com.fivucsas.identity.domain.model.role;

import com.fivucsas.identity.domain.model.permission.Permission;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Pure domain model for Role.
 * Represents a collection of permissions, scoped to a tenant.
 *
 * No JPA annotations - this is a pure domain concept.
 * Business logic lives here; persistence is handled by infrastructure.
 */
public class Role {

    private final UUID id;
    private UUID tenantId;
    private String name;
    private String description;
    private boolean systemRole;
    private boolean active;
    private final Set<Permission> permissions;
    private final Instant createdAt;
    private Instant updatedAt;
    private Instant deletedAt;

    private Role(UUID id, UUID tenantId, String name, String description,
                 boolean systemRole, boolean active, Set<Permission> permissions,
                 Instant createdAt, Instant updatedAt, Instant deletedAt) {
        this.id = id;
        this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID cannot be null");
        this.name = Objects.requireNonNull(name, "Role name cannot be null");
        this.description = description;
        this.systemRole = systemRole;
        this.active = active;
        this.permissions = permissions != null ? new HashSet<>(permissions) : new HashSet<>();
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.deletedAt = deletedAt;
    }

    // ========== Factory Methods ==========

    /**
     * Creates a new role for a tenant.
     */
    public static Role create(UUID tenantId, String name, String description, boolean systemRole) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Role name cannot be empty");
        }
        return new Role(null, tenantId, name.trim(), description, systemRole, true,
                        new HashSet<>(), Instant.now(), Instant.now(), null);
    }

    /**
     * Reconstitutes a role from persistence.
     */
    public static Role reconstitute(UUID id, UUID tenantId, String name, String description,
                                    boolean systemRole, boolean active, Set<Permission> permissions,
                                    Instant createdAt, Instant updatedAt, Instant deletedAt) {
        return new Role(id, tenantId, name, description, systemRole, active,
                        permissions, createdAt, updatedAt, deletedAt);
    }

    // ========== Business Methods ==========

    public void addPermission(Permission permission) {
        if (permission != null) {
            permissions.add(permission);
            this.updatedAt = Instant.now();
        }
    }

    public void removePermission(Permission permission) {
        if (permission != null) {
            permissions.remove(permission);
            this.updatedAt = Instant.now();
        }
    }

    public boolean hasPermission(String permissionName) {
        return permissions.stream()
            .anyMatch(p -> p.getName().equals(permissionName) ||
                          p.getAuthorityName().equals(permissionName));
    }

    public boolean hasPermission(String resource, String action) {
        String permissionString = resource + ":" + action;
        return hasPermission(permissionString);
    }

    public Set<String> getPermissionStrings() {
        return permissions.stream()
            .map(Permission::getAuthorityName)
            .collect(Collectors.toSet());
    }

    public Set<String> getPermissionAuthorities() {
        return permissions.stream()
            .map(Permission::getAuthorityName)
            .collect(Collectors.toSet());
    }

    public Set<String> getAuthorities() {
        Set<String> authorities = new HashSet<>();
        authorities.add("ROLE_" + this.name);
        authorities.addAll(getPermissionAuthorities());
        return authorities;
    }

    public void updateDetails(String name, String description) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Role name cannot be empty");
        }
        this.name = name.trim();
        this.description = description;
        this.updatedAt = Instant.now();
    }

    public void updateName(String name) {
        if (name != null && !name.trim().isEmpty()) {
            this.name = name.trim();
            this.updatedAt = Instant.now();
        }
    }

    public void deactivate() {
        this.active = false;
        this.updatedAt = Instant.now();
    }

    public void activate() {
        this.active = true;
        this.updatedAt = Instant.now();
    }

    public void softDelete() {
        this.deletedAt = Instant.now();
        this.active = false;
        this.updatedAt = Instant.now();
    }

    public boolean isDeleted() {
        return this.deletedAt != null;
    }

    public boolean isSystemRole() {
        return this.systemRole;
    }

    public boolean isActive() {
        return this.active;
    }

    // ========== Getters ==========

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public Set<Permission> getPermissions() {
        return Collections.unmodifiableSet(permissions);
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getDeletedAt() {
        return deletedAt;
    }

    // ========== Equality ==========

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Role role)) return false;
        return id != null && id.equals(role.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public String toString() {
        return "Role{id=" + id + ", name='" + name + "', systemRole=" + systemRole +
               ", active=" + active + "}";
    }
}
