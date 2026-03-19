package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;
import com.fivucsas.identity.application.port.input.GetStatisticsUseCase;
import com.fivucsas.identity.dto.AuditLogDto;
import com.fivucsas.identity.dto.StatisticsDto;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REST controller for audit logs and statistics.
 *
 * Merges: AuditLogController + StatisticsController
 */
@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Audit Logs", description = "Audit log and statistics endpoints")
public class AuditLogController {

    private final AuditLogRepository auditLogRepository;
    private final GetStatisticsUseCase getStatisticsUseCase;

    @GetMapping("/api/v1/audit-logs")
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

    @GetMapping("/api/v1/audit-logs/action-types")
    @Operation(summary = "Get available audit log action types")
    @PreAuthorize("hasPermission(null, 'audit', 'read')")
    public ResponseEntity<List<String>> getActionTypes() {
        return ResponseEntity.ok(List.of(
            "USER_CREATED", "USER_UPDATED", "USER_DELETED",
            "USER_AUTHENTICATED", "USER_REGISTERED", "USER_LOGGED_OUT",
            "BIOMETRIC_ENROLLED", "BIOMETRIC_VERIFIED", "BIOMETRIC_DELETED",
            "ROLE_CREATED", "ROLE_UPDATED", "ROLE_DELETED",
            "ROLE_ASSIGNED", "ROLE_REVOKED",
            "PERMISSION_GRANTED", "PERMISSION_REVOKED",
            "TENANT_CREATED", "TENANT_UPDATED", "TENANT_DELETED",
            "TENANT_ACTIVATED", "TENANT_SUSPENDED",
            "SETTINGS_UPDATED", "PASSWORD_CHANGED", "PASSWORD_RESET",
            "EMAIL_VERIFIED", "PHONE_VERIFIED",
            "ENROLLMENT_STARTED", "ENROLLMENT_COMPLETED", "ENROLLMENT_FAILED",
            "AUTH_FLOW_CREATED", "AUTH_FLOW_UPDATED", "AUTH_FLOW_DELETED",
            "DEVICE_REGISTERED", "DEVICE_REMOVED",
            "GUEST_INVITED", "GUEST_ACCEPTED", "GUEST_REVOKED"
        ));
    }

    @GetMapping("/api/v1/audit-logs/{id}")
    @Operation(summary = "Get audit log by ID")
    @PreAuthorize("hasPermission(null, 'audit', 'read')")
    public ResponseEntity<AuditLogDto> getAuditLogById(@PathVariable String id) {
        log.info("GET /api/v1/audit-logs/{}", id);

        AuditLog auditLog = auditLogRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> new com.fivucsas.identity.exception.ResourceNotFoundException("AuditLog not found: " + id));

        return ResponseEntity.ok(mapToDto(auditLog));
    }

    // --- Statistics endpoints merged from StatisticsController ---

    @GetMapping("/api/v1/statistics/dashboard")
    @Operation(summary = "Get dashboard statistics (alias)")
    @PreAuthorize("hasAuthority('analytics:view')")
    public ResponseEntity<StatisticsDto> getDashboardStatistics() {
        return getStatistics();
    }

    @GetMapping("/api/v1/statistics")
    @Operation(summary = "Get system statistics")
    @PreAuthorize("hasAuthority('analytics:view')")
    public ResponseEntity<StatisticsDto> getStatistics() {
        log.info("GET /api/v1/statistics - Get system statistics");

        StatisticsResponse response = getStatisticsUseCase.execute();

        double avgVerifications = response.getTotalUsers() > 0
            ? (double) response.getTotalVerifications() / response.getTotalUsers()
            : 0.0;

        StatisticsDto dto = StatisticsDto.builder()
            .totalUsers(response.getTotalUsers())
            .activeUsers(response.getActiveUsers())
            .inactiveUsers(response.getInactiveUsers())
            .suspendedUsers(response.getSuspendedUsers())
            .biometricEnrolledUsers(response.getBiometricEnrolledUsers())
            .totalVerifications(response.getTotalVerifications())
            .averageVerificationsPerUser(avgVerifications)
            .totalTenants(response.getTotalTenants())
            .pendingEnrollments(response.getPendingEnrollments())
            .successfulEnrollments(response.getSuccessfulEnrollments())
            .failedEnrollments(response.getFailedEnrollments())
            .authSuccessRate(response.getAuthSuccessRate())
            .verificationSuccessRate(response.getVerificationSuccessRate())
            .build();

        return ResponseEntity.ok(dto);
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
