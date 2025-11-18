package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;
import com.fivucsas.identity.application.port.input.GetStatisticsUseCase;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.UserStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

        return StatisticsResponse.builder()
            .totalUsers(totalUsers)
            .activeUsers(activeUsers)
            .inactiveUsers(inactiveUsers)
            .suspendedUsers(suspendedUsers)
            .biometricEnrolledUsers(biometricEnrolledUsers)
            .totalVerifications(totalVerifications != null ? totalVerifications : 0L)
            .build();
    }
}
