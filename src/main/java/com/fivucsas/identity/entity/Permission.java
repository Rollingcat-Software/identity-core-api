package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;

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
        return Permission.builder()
            .name(resource.toUpperCase() + ":" + action.toUpperCase())
            .description(description)
            .resource(resource.toUpperCase())
            .action(action.toUpperCase())
            .build();
    }

    /**
     * Gets the full permission string.
     */
    public String getPermissionString() {
        return resource + ":" + action;
    }
}
