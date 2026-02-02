package com.fivucsas.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogDto {

    private String id;
    private String userId;
    private String tenantId;
    private String action;
    private String entityType;
    private String entityId;
    private Boolean success;
    private String errorMessage;
    private String ipAddress;
    private String userAgent;
    private Map<String, Object> details;
    private Instant timestamp;
}
