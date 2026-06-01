package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * Command for updating an existing user.
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains update data
 * - Command Pattern: Represents user update action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserCommand {

    private String userId;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String address;

    /**
     * Platform-tier ({@link com.fivucsas.identity.entity.UserType} NAME) to set.
     * {@code null} = leave unchanged. ROOT-caller-only when it changes the tier.
     */
    private String userType;

    /**
     * Complete desired set of within-tenant RBAC role ids (replace semantics).
     * {@code null} = leave role assignments untouched; empty = revoke all.
     */
    private List<UUID> roleIds;
}
