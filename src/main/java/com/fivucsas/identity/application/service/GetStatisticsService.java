package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;
import com.fivucsas.identity.application.port.input.GetStatisticsUseCase;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case service for retrieving system statistics.
 *
 * Implements the GetStatisticsUseCase input port.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GetStatisticsService implements GetStatisticsUseCase {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(readOnly = true)
    public StatisticsResponse execute() {
        log.info("Fetching system statistics");

        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countByStatus(UserStatus.ACTIVE);
        long inactiveUsers = userRepository.countByStatus(UserStatus.INACTIVE);
        long suspendedUsers = userRepository.countByStatus(UserStatus.SUSPENDED);
        long biometricEnrolledUsers = userRepository.countByIsBiometricEnrolled(true);
        Long totalVerifications = userRepository.sumVerificationCount();
        long totalTenants = tenantRepository.count();

        // Enrollment statistics: calculate from actual data
        long successfulEnrollments = biometricEnrolledUsers;
        long pendingEnrollments = totalUsers - biometricEnrolledUsers;
        long failedEnrollments = 0L; // Will be calculated from biometric verification logs when available

        // Calculate rates from actual audit log data
        double authSuccessRate = 0.0;
        double verificationSuccessRate = 0.0;

        try {
            var successLogs = auditLogRepository.findBySuccessOrderByCreatedAtDesc(true, PageRequest.of(0, 1));
            var failedLogs = auditLogRepository.findBySuccessOrderByCreatedAtDesc(false, PageRequest.of(0, 1));
            long totalSuccess = successLogs.getTotalElements();
            long totalFailed = failedLogs.getTotalElements();
            long totalOps = totalSuccess + totalFailed;
            if (totalOps > 0) {
                authSuccessRate = Math.round((totalSuccess * 100.0) / totalOps * 10) / 10.0;
            }
            // Verification success rate based on actual verification count
            if (totalVerifications != null && totalVerifications > 0) {
                // Calculate from biometric verification logs if available
                verificationSuccessRate = Math.round((totalVerifications * 100.0) / (totalVerifications + failedEnrollments) * 10) / 10.0;
            }
        } catch (Exception e) {
            log.debug("Could not compute rates from audit logs: {}", e.getMessage());
        }

        return StatisticsResponse.builder()
            .totalUsers(totalUsers)
            .activeUsers(activeUsers)
            .inactiveUsers(inactiveUsers)
            .suspendedUsers(suspendedUsers)
            .biometricEnrolledUsers(biometricEnrolledUsers)
            .totalVerifications(totalVerifications != null ? totalVerifications : 0L)
            .totalTenants(totalTenants)
            .pendingEnrollments(pendingEnrollments)
            .successfulEnrollments(successfulEnrollments)
            .failedEnrollments(failedEnrollments)
            .authSuccessRate(authSuccessRate)
            .verificationSuccessRate(verificationSuccessRate)
            .build();
    }
}
