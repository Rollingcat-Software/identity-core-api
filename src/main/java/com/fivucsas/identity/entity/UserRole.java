package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Junction entity for User-Role many-to-many relationship.
 *
 * Contains audit information:
 * - assignedAt: When the role was assigned
 * - assignedBy: Who assigned the role (user ID)
 * - expiresAt: Optional expiration for time-limited role assignments
 */
@Entity
@Table(name = "user_roles")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class UserRole {

    @EmbeddedId
    private UserRoleId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("userId")
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("roleId")
    @JoinColumn(name = "role_id", insertable = false, updatable = false)
    private Role role;

    @Column(name = "assigned_at", nullable = false)
    @Builder.Default
    private Instant assignedAt = Instant.now();

    @Column(name = "assigned_by")
    private UUID assignedBy;

    @Column(name = "expires_at")
    @Setter
    private Instant expiresAt;

    // ========== Business Methods ==========

    /**
     * Checks if this role assignment has expired.
     */
    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }

    /**
     * Checks if this role assignment is currently valid.
     * Valid means: not expired AND role is active AND role is not deleted.
     */
    public boolean isValid() {
        return !isExpired() && role != null && role.isActive() && !role.isDeleted();
    }

    /**
     * Returns the user ID from the composite key.
     */
    public UUID getUserId() {
        return id != null ? id.getUserId() : null;
    }

    /**
     * Returns the role ID from the composite key.
     */
    public UUID getRoleId() {
        return id != null ? id.getRoleId() : null;
    }

    /**
     * Factory method to create a new UserRole assignment.
     */
    public static UserRole create(User user, Role role, UUID assignedBy, Instant expiresAt) {
        UserRoleId id = UserRoleId.of(user.getId(), role.getId());
        return UserRole.builder()
                .id(id)
                .user(user)
                .role(role)
                .assignedAt(Instant.now())
                .assignedBy(assignedBy)
                .expiresAt(expiresAt)
                .build();
    }

    /**
     * Factory method to create a non-expiring UserRole assignment.
     */
    public static UserRole create(User user, Role role, UUID assignedBy) {
        return create(user, role, assignedBy, null);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserRole)) return false;
        UserRole userRole = (UserRole) o;
        return id != null && id.equals(userRole.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }

    @Override
    public String toString() {
        return "UserRole{" +
                "userId=" + (id != null ? id.getUserId() : null) +
                ", roleId=" + (id != null ? id.getRoleId() : null) +
                ", assignedAt=" + assignedAt +
                ", expiresAt=" + expiresAt +
                ", expired=" + isExpired() +
                '}';
    }
}
