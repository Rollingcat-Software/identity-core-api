package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Response DTO for user-role assignment data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRoleResponse {

    private String userId;
    private String userEmail;
    private String userName;
    private String roleId;
    private String roleName;
    private Instant assignedAt;
    private String assignedBy;
    private Instant expiresAt;
    private boolean expired;
}
