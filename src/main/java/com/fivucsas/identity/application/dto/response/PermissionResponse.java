package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for permission data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionResponse {

    private String id;
    private String name;
    private String description;
    private String resource;
    private String action;
    private String authority;  // Combined resource:action format
}
