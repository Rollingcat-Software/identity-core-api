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
    private Long enrolledUsers;
    private Long totalVerifications;
    private Double averageVerificationsPerUser;
}
