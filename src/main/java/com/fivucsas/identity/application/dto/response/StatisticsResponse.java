package com.fivucsas.identity.application.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response for system statistics.
 *
 * Following principles:
 * - Single Responsibility: Only contains statistics data
 * - Data Transfer: No business logic
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StatisticsResponse {

    private long totalUsers;
    private long activeUsers;
    private long inactiveUsers;
    private long suspendedUsers;
    private long biometricEnrolledUsers;
    private long totalVerifications;
    private long totalTenants;
    private long pendingEnrollments;
    private long successfulEnrollments;
    private long failedEnrollments;
    private double authSuccessRate;
    private double verificationSuccessRate;
}
