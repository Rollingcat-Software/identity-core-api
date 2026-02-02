package com.fivucsas.identity.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StatisticsDto {

    private Long totalUsers;
    private Long activeUsers;
    private Long inactiveUsers;
    private Long suspendedUsers;
    private Long biometricEnrolledUsers;
    private Long totalVerifications;
    private Double averageVerificationsPerUser;
    private Long totalTenants;
    private Long pendingEnrollments;
    private Long successfulEnrollments;
    private Long failedEnrollments;
    private Double authSuccessRate;
    private Double verificationSuccessRate;
}
