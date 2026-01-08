package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * Response DTO for role data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleResponse {

    private String id;
    private String tenantId;
    private String name;
    private String description;
    private boolean systemRole;
    private boolean active;
    private List<PermissionResponse> permissions;
    private Instant createdAt;
    private Instant updatedAt;
}
