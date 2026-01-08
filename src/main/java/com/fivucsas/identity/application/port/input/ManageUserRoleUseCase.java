package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.command.AssignRoleToUserCommand;
import com.fivucsas.identity.application.dto.command.RevokeRoleFromUserCommand;
import com.fivucsas.identity.application.dto.query.GetRoleUsersQuery;
import com.fivucsas.identity.application.dto.query.GetUserRolesQuery;
import com.fivucsas.identity.application.dto.response.UserRoleResponse;

import java.util.List;

/**
 * Input port for user-role assignment operations.
 * Defines use cases for assigning and revoking roles from users.
 */
public interface ManageUserRoleUseCase {

    /**
     * Assigns a role to a user.
     *
     * @param command the assign role to user command
     */
    void assignRoleToUser(AssignRoleToUserCommand command);

    /**
     * Revokes a role from a user.
     *
     * @param command the revoke role from user command
     */
    void revokeRoleFromUser(RevokeRoleFromUserCommand command);

    /**
     * Retrieves all roles assigned to a user.
     *
     * @param query the get user roles query
     * @return list of user role responses
     */
    List<UserRoleResponse> getUserRoles(GetUserRolesQuery query);

    /**
     * Retrieves all users assigned to a role.
     *
     * @param query the get role users query
     * @return list of user role responses
     */
    List<UserRoleResponse> getRoleUsers(GetRoleUsersQuery query);
}
