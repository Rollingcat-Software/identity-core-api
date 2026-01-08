package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Permission entity for RBAC.
 * Represents a single permission in the format "resource:action".
 *
 * Permissions are immutable after creation (only description can be updated).
 * Default permissions are created via database migration V3.
 */
@Entity
@Table(name = "permissions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 100)
    private String name;  // e.g., "user.read"

    @Column(length = 500)
    @Setter
    private String description;

    @Column(nullable = false, length = 100)
    private String resource;  // e.g., "user", "biometric", "role"

    @Column(nullable = false, length = 50)
    private String action;  // e.g., "read", "create", "update", "delete"

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;

    /**
     * Returns the authority name in Spring Security format.
     * Format: "resource:action" (e.g., "user:read")
     */
    public String getAuthorityName() {
        return resource + ":" + action;
    }

    /**
     * Factory method to create a new permission.
     */
    public static Permission create(String name, String description, String resource, String action) {
        return Permission.builder()
                .name(name)
                .description(description)
                .resource(resource)
                .action(action)
                .build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Permission)) return false;
        Permission that = (Permission) o;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }

    @Override
    public String toString() {
        return "Permission{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", resource='" + resource + '\'' +
                ", action='" + action + '\'' +
                '}';
    }
}
