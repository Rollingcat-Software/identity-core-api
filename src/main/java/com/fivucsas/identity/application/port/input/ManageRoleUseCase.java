package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.*;
import com.fivucsas.identity.application.dto.query.*;
import com.fivucsas.identity.application.dto.response.RoleResponse;

import java.util.List;

/**
 * Input port for role management operations.
 * Defines use cases for CRUD operations on roles and permission assignments.
 */
public interface ManageRoleUseCase {

    /**
     * Creates a new role.
     *
     * @param command the create role command
     * @return the created role response
     */
    RoleResponse createRole(CreateRoleCommand command);

    /**
     * Retrieves a role by ID.
     *
     * @param query the get role by ID query
     * @return the role response
     */
    RoleResponse getRoleById(GetRoleByIdQuery query);

    /**
     * Retrieves all roles.
     *
     * @param query the get all roles query
     * @return list of role responses
     */
    List<RoleResponse> getAllRoles(GetAllRolesQuery query);

    /**
     * Retrieves roles for a specific tenant.
     *
     * @param query the get roles by tenant query
     * @return list of role responses
     */
    List<RoleResponse> getRolesByTenant(GetRolesByTenantQuery query);

    /**
     * Updates an existing role.
     *
     * @param command the update role command
     * @return the updated role response
     */
    RoleResponse updateRole(UpdateRoleCommand command);

    /**
     * Deletes a role (soft delete).
     *
     * @param roleId the role ID to delete
     */
    void deleteRole(String roleId);

    /**
     * Assigns a permission to a role.
     *
     * @param command the assign permission command
     */
    void assignPermissionToRole(AssignPermissionCommand command);

    /**
     * Revokes a permission from a role.
     *
     * @param command the revoke permission command
     */
    void revokePermissionFromRole(RevokePermissionCommand command);
}
