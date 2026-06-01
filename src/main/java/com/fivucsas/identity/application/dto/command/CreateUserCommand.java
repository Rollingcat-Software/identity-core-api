package com.fivucsas.identity.application.dto.command;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * Command for creating a new user (admin operation).
 *
 * Follows CQRS pattern - this is a write operation command.
 *
 * Following principles:
 * - Single Responsibility: Only contains data for user creation
 * - Command Pattern: Represents user creation action
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserCommand {

    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String address;
    private String idNumber;
    private String role; // Optional - role name to assign after creation
    private String tenantId; // Optional - tenant to assign user to

    /**
     * Platform-tier ({@link com.fivucsas.identity.entity.UserType} NAME) for the
     * new user. {@code null} = system default (TENANT_MEMBER). Setting ROOT /
     * TENANT_ADMIN is ROOT-caller-only.
     */
    private String userType;

    /** Within-tenant RBAC role ids to assign to the new user. */
    private List<UUID> roleIds;
}
