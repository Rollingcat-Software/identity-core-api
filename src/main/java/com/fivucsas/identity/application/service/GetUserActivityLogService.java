package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.query.GetUserActivityLogQuery;
import com.fivucsas.identity.application.dto.response.ActivityLogResponse;
import com.fivucsas.identity.application.dto.response.SessionResponse;
import com.fivucsas.identity.application.port.input.GetUserActivityLogUseCase;
import com.fivucsas.identity.domain.exception.UserNotFoundException;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for getting user activity log.
 *
 * Implements the GetUserActivityLogUseCase input port.
 * Returns paginated list of user's own audit logs.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GetUserActivityLogService implements GetUserActivityLogUseCase {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(readOnly = true)
    public Page<ActivityLogResponse> execute(GetUserActivityLogQuery query) {
        log.info("Get activity log request for user: {}", query.getEmail());

        User user = userRepository.findByEmail(query.getEmail())
            .orElseThrow(() -> new UserNotFoundException("User not found with email: " + query.getEmail()));

        Pageable pageable = PageRequest.of(query.getPage(), query.getSize());

        Page<AuditLog> auditLogs = auditLogRepository.findByUserIdOrderByCreatedAtDesc(user.getId(), pageable);

        log.info("Found {} activity logs for user: {}", auditLogs.getTotalElements(), query.getEmail());

        return auditLogs.map(this::mapToActivityLogResponse);
    }

    private ActivityLogResponse mapToActivityLogResponse(AuditLog auditLog) {
        String deviceInfo = SessionResponse.extractDeviceInfo(auditLog.getEffectiveUserAgent());

        return ActivityLogResponse.builder()
            .id(auditLog.getId().toString())
            .action(auditLog.getAction())
            .description(ActivityLogResponse.generateDescription(auditLog.getAction()))
            .ipAddress(auditLog.getIpAddress())
            .deviceInfo(deviceInfo)
            .success(auditLog.getSuccess())
            .errorMessage(auditLog.getErrorMessage())
            .createdAt(auditLog.getCreatedAt())
            .build();
    }
}
