package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.Filter;
import org.hibernate.annotations.FilterDef;
import org.hibernate.annotations.ParamDef;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Role entity representing a collection of permissions.
 *
 * Roles are tenant-scoped, allowing different tenants to have
 * different role definitions.
 */
@Entity
@Table(name = "roles", indexes = {
    @Index(name = "idx_roles_tenant_id", columnList = "tenant_id")
})
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = UUID.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    @Setter
    private String description;

    @Column(name = "is_system_role")
    @Builder.Default
    private boolean isSystemRole = false;

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
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    // ========== Business Methods ==========

    /**
     * Adds a permission to this role.
     */
    public void addPermission(Permission permission) {
        if (permission != null) {
            permissions.add(permission);
        }
    }

    /**
     * Removes a permission from this role.
     */
    public void removePermission(Permission permission) {
        if (permission != null) {
            permissions.remove(permission);
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
     * Checks if role has permission for resource and action.
     */
    public boolean hasPermission(String resource, String action) {
        String permissionString = resource + ":" + action;
        return hasPermission(permissionString);
    }

    /**
     * Gets all permission strings for this role.
     */
    public Set<String> getPermissionStrings() {
        Set<String> permStrings = new HashSet<>();
        for (Permission p : permissions) {
            permStrings.add(p.getAuthorityName());
        }
        return permStrings;
    }

    /**
     * Returns only permission authority names.
     * Alias for getPermissionStrings() for compatibility.
     */
    public Set<String> getPermissionAuthorities() {
        return permissions.stream()
                .map(Permission::getAuthorityName)
                .collect(Collectors.toSet());
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
        authorities.addAll(getPermissionAuthorities());
        return authorities;
    }

    /**
     * Updates role details.
     */
    public void updateDetails(String name, String description) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Role name cannot be empty");
        }
        this.name = name;
        this.description = description;
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
     * Checks if role is a system role.
     */
    public boolean isSystemRole() {
        return this.isSystemRole;
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
                ", isSystemRole=" + isSystemRole +
                ", active=" + active +
                '}';
    }
}
