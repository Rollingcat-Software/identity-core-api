package com.fivucsas.identity.controller;

import com.fivucsas.identity.dto.AuditLogDto;
import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.repository.AuditLogRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/audit-logs")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Audit Logs", description = "Audit log endpoints")
public class AuditLogController {

    private final AuditLogRepository auditLogRepository;

    @GetMapping
    @Operation(summary = "Get audit logs with pagination")
    @PreAuthorize("hasPermission(null, 'audit', 'read')")
    public ResponseEntity<Map<String, Object>> getAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String userId) {

        log.info("GET /api/v1/audit-logs - page={}, size={}", page, size);

        PageRequest pageRequest = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<AuditLog> auditLogs;

        if (action != null && !action.isBlank()) {
            auditLogs = auditLogRepository.findByActionOrderByCreatedAtDesc(action, pageRequest);
        } else if (userId != null && !userId.isBlank()) {
            auditLogs = auditLogRepository.findByUserIdOrderByCreatedAtDesc(UUID.fromString(userId), pageRequest);
        } else {
            auditLogs = auditLogRepository.findAll(pageRequest);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("content", auditLogs.getContent().stream().map(this::mapToDto).toList());
        response.put("totalElements", auditLogs.getTotalElements());
        response.put("totalPages", auditLogs.getTotalPages());
        response.put("page", auditLogs.getNumber());
        response.put("size", auditLogs.getSize());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get audit log by ID")
    @PreAuthorize("hasPermission(null, 'audit', 'read')")
    public ResponseEntity<AuditLogDto> getAuditLogById(@PathVariable String id) {
        log.info("GET /api/v1/audit-logs/{}", id);

        AuditLog auditLog = auditLogRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> new com.fivucsas.identity.exception.ResourceNotFoundException("AuditLog not found: " + id));

        return ResponseEntity.ok(mapToDto(auditLog));
    }

    private AuditLogDto mapToDto(AuditLog auditLog) {
        return AuditLogDto.builder()
                .id(auditLog.getId().toString())
                .userId(auditLog.getUserId() != null ? auditLog.getUserId().toString() : null)
                .tenantId(auditLog.getTenantId() != null ? auditLog.getTenantId().toString() : null)
                .action(auditLog.getAction())
                .entityType(auditLog.getResourceType())
                .entityId(auditLog.getResourceId() != null ? auditLog.getResourceId().toString() : null)
                .success(auditLog.getSuccess())
                .errorMessage(auditLog.getErrorMessage())
                .ipAddress(auditLog.getIpAddress())
                .userAgent(auditLog.getEffectiveUserAgent())
                .details(auditLog.getMetadata())
                .timestamp(auditLog.getCreatedAt())
                .build();
    }
}
