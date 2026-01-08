package com.fivucsas.identity.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

/**
 * Composite primary key for UserRole entity.
 * Combines user_id and role_id.
 */
@Embeddable
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRoleId implements Serializable {

    private static final long serialVersionUID = 1L;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "role_id")
    private UUID roleId;

    /**
     * Factory method for creating UserRoleId.
     */
    public static UserRoleId of(UUID userId, UUID roleId) {
        return new UserRoleId(userId, roleId);
    }
}
