package com.fivucsas.identity.service;

import com.fivucsas.identity.dto.StatisticsDto;
import com.fivucsas.identity.entity.UserStatus;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class StatisticsService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public StatisticsDto getStatistics() {
        log.info("Calculating system statistics");

        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countByStatus(UserStatus.ACTIVE);
        long inactiveUsers = userRepository.countByStatus(UserStatus.INACTIVE);
        long suspendedUsers = userRepository.countByStatus(UserStatus.SUSPENDED);
        long enrolledUsers = userRepository.countByIsBiometricEnrolled(true);
        Long totalVerifications = userRepository.sumVerificationCount();

        double avgVerifications = totalUsers > 0 
                ? (totalVerifications != null ? totalVerifications.doubleValue() / totalUsers : 0.0)
                : 0.0;

        return StatisticsDto.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .inactiveUsers(inactiveUsers)
                .suspendedUsers(suspendedUsers)
                .biometricEnrolledUsers(enrolledUsers)
                .totalVerifications(totalVerifications != null ? totalVerifications : 0L)
                .averageVerificationsPerUser(Math.round(avgVerifications * 100.0) / 100.0)
                .build();
    }
}
