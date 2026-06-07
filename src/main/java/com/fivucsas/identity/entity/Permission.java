package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Locale;
import java.util.UUID;

/**
 * Permission entity representing a specific action that can be performed.
 *
 * Permissions follow the format: RESOURCE:ACTION
 * Examples: USER:READ, USER:WRITE, TENANT:MANAGE, BIOMETRIC:ENROLL
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
    private String name;

    @Column(length = 500)
    private String description;

    @Column(nullable = false, length = 50)
    private String resource;

    @Column(nullable = false, length = 50)
    private String action;

    /**
     * Creates a permission from resource and action.
     */
    public static Permission of(String resource, String action, String description) {
        // Locale.ROOT: permission/resource/action are ASCII security identifiers.
        // A bare toUpperCase()/toLowerCase() under the Turkish locale maps i↔İ /
        // I↔ı, which would mint a permission name that no security check can match.
        return Permission.builder()
            .name(resource.toUpperCase(Locale.ROOT) + ":" + action.toUpperCase(Locale.ROOT))
            .description(description)
            .resource(resource.toUpperCase(Locale.ROOT))
            .action(action.toUpperCase(Locale.ROOT))
            .build();
    }

    /**
     * Gets the full permission string.
     */
    public String getPermissionString() {
        return resource + ":" + action;
    }

    /**
     * Returns the authority name in Spring Security format.
     * Format: "resource:action" (e.g., "user:read")
     * Alias for getPermissionString() for Spring Security compatibility.
     */
    public String getAuthorityName() {
        return resource.toLowerCase(Locale.ROOT) + ":" + action.toLowerCase(Locale.ROOT);
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
