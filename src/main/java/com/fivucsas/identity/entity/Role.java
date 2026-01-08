package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Role entity for RBAC.
 * Roles can be system-wide (tenant_id = null) or tenant-specific.
 *
 * System roles cannot be modified or deleted.
 * Default roles are created via database migration V3.
 */
@Entity
@Table(name = "roles")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    @Setter
    private String description;

    @Column(name = "is_system_role", nullable = false)
    @Builder.Default
    private boolean systemRole = false;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    // ========== Business Methods ==========

    /**
     * Adds a permission to this role.
     */
    public void addPermission(Permission permission) {
        if (permission != null) {
            this.permissions.add(permission);
        }
    }

    /**
     * Removes a permission from this role.
     */
    public void removePermission(Permission permission) {
        if (permission != null) {
            this.permissions.remove(permission);
        }
    }

    /**
     * Checks if role has a specific permission.
     */
    public boolean hasPermission(String permissionName) {
        return permissions.stream()
                .anyMatch(p -> p.getName().equals(permissionName) ||
                              p.getAuthorityName().equals(permissionName));
    }

    /**
     * Deactivates the role.
     * Deactivated roles are not loaded for users.
     */
    public void deactivate() {
        this.active = false;
    }

    /**
     * Activates the role.
     */
    public void activate() {
        this.active = true;
    }

    /**
     * Soft deletes the role.
     * Soft-deleted roles are not visible in queries.
     */
    public void softDelete() {
        this.deletedAt = Instant.now();
        this.active = false;
    }

    /**
     * Checks if role is soft-deleted.
     */
    public boolean isDeleted() {
        return this.deletedAt != null;
    }

    /**
     * Updates the role name.
     */
    public void updateName(String name) {
        if (name != null && !name.trim().isEmpty()) {
            this.name = name.trim();
        }
    }

    /**
     * Returns all authority names for this role.
     * Includes both role name (ROLE_X) and permission names (resource:action).
     */
    public Set<String> getAuthorities() {
        Set<String> authorities = new HashSet<>();
        // Add role as authority
        authorities.add("ROLE_" + this.name);
        // Add all permissions
        authorities.addAll(permissions.stream()
                .map(Permission::getAuthorityName)
                .collect(Collectors.toSet()));
        return authorities;
    }

    /**
     * Returns only permission authority names.
     */
    public Set<String> getPermissionAuthorities() {
        return permissions.stream()
                .map(Permission::getAuthorityName)
                .collect(Collectors.toSet());
    }

    /**
     * Factory method to create a new tenant-specific role.
     */
    public static Role createForTenant(UUID tenantId, String name, String description) {
        return Role.builder()
                .tenantId(tenantId)
                .name(name)
                .description(description)
                .systemRole(false)
                .active(true)
                .build();
    }

    /**
     * Factory method to create a new system-wide role.
     */
    public static Role createSystemRole(String name, String description) {
        return Role.builder()
                .tenantId(null)
                .name(name)
                .description(description)
                .systemRole(true)
                .active(true)
                .build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Role)) return false;
        Role role = (Role) o;
        return id != null && id.equals(role.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", tenantId=" + tenantId +
                ", systemRole=" + systemRole +
                ", active=" + active +
                '}';
    }
}
