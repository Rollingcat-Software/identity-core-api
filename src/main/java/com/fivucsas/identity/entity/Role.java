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
    private String description;

    @Column(name = "is_system_role")
    @Builder.Default
    private boolean isSystemRole = false;

    @ManyToMany(fetch = FetchType.EAGER)
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
        permissions.remove(permission);
    }

    /**
     * Checks if role has a specific permission.
     */
    public boolean hasPermission(String permissionName) {
        return permissions.stream()
            .anyMatch(p -> p.getName().equals(permissionName));
    }

    /**
     * Checks if role has permission for resource and action.
     */
    public boolean hasPermission(String resource, String action) {
        String permissionString = resource.toUpperCase() + ":" + action.toUpperCase();
        return hasPermission(permissionString);
    }

    /**
     * Gets all permission strings for this role.
     */
    public Set<String> getPermissionStrings() {
        Set<String> permStrings = new HashSet<>();
        for (Permission p : permissions) {
            permStrings.add(p.getPermissionString());
        }
        return permStrings;
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
}
