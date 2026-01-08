package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.query.GetPermissionByIdQuery;
import com.fivucsas.identity.application.dto.response.PermissionResponse;

import java.util.List;

/**
 * Input port for permission management operations.
 * Permissions are read-only (created via database migrations).
 */
public interface ManagePermissionUseCase {

    /**
     * Retrieves a permission by ID.
     *
     * @param query the get permission by ID query
     * @return the permission response
     */
    PermissionResponse getPermissionById(GetPermissionByIdQuery query);

    /**
     * Retrieves all permissions.
     *
     * @return list of all permission responses
     */
    List<PermissionResponse> getAllPermissions();

    /**
     * Retrieves permissions for a specific resource.
     *
     * @param resource the resource name (e.g., "user", "biometric")
     * @return list of permission responses for the resource
     */
    List<PermissionResponse> getPermissionsByResource(String resource);
}
