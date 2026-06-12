package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;
import com.fivucsas.identity.application.port.input.GetStatisticsUseCase;
import com.fivucsas.identity.domain.model.user.UserStatus;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import com.fivucsas.identity.application.port.output.AuditLogQueryPort;
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

    private final UserDomainRepository userRepository;
    private final TenantRepository tenantRepository;
    private final AuditLogQueryPort auditLogRepository;

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

        // Enrollment statistics: calculate from actual data.
        long successfulEnrollments = biometricEnrolledUsers;
        long pendingEnrollments = totalUsers - biometricEnrolledUsers;
        // We do NOT track a distinct failed-enrollment count yet (no source in
        // user_enrollments / biometric logs surfaced to this query), so we
        // report it honestly as 0 rather than inferring it. Do NOT use this as a
        // divisor for a "success rate" — that previously made every rate 100%.
        long failedEnrollments = 0L;

        // Success rates: derived ONLY from real audit-log success/failure counts.
        // The audit success/failure tally is the single real outcome signal we
        // have, and it is what backs authSuccessRate. There is no separate
        // verification-outcome source, so verificationSuccessRate is NOT
        // fabricated from totalVerifications/(totalVerifications + 0) (which is
        // mathematically always 100%); it stays 0.0 ("not tracked") until a real
        // pass/fail verification metric exists. Raw counts above remain truthful.
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
