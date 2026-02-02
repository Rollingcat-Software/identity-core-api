package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;
import com.fivucsas.identity.application.port.input.GetStatisticsUseCase;
import com.fivucsas.identity.dto.StatisticsDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for statistics endpoints.
 *
 * Refactored to use Hexagonal Architecture input ports (use cases).
 */
@RestController
@RequestMapping("/api/v1/statistics")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Statistics", description = "System statistics")
public class StatisticsController {

    private final GetStatisticsUseCase getStatisticsUseCase;

    @GetMapping
    @Operation(summary = "Get system statistics")
    @PreAuthorize("hasAuthority('analytics:view')")
    public ResponseEntity<StatisticsDto> getStatistics() {
        log.info("GET /api/v1/statistics - Get system statistics");

        StatisticsResponse response = getStatisticsUseCase.execute();

        return ResponseEntity.ok(mapToStatisticsDto(response));
    }

    private StatisticsDto mapToStatisticsDto(StatisticsResponse response) {
        double avgVerifications = response.getTotalUsers() > 0
            ? (double) response.getTotalVerifications() / response.getTotalUsers()
            : 0.0;

        return StatisticsDto.builder()
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
    }
}
