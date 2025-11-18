package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.UserStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("GetStatisticsService Tests")
class GetStatisticsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private GetStatisticsService getStatisticsService;

    @Nested
    @DisplayName("Get Statistics")
    class GetStatistics {

        @Test
        @DisplayName("Should return all statistics successfully")
        void shouldReturnAllStatisticsSuccessfully() {
            // Given
            when(userRepository.count()).thenReturn(100L);
            when(userRepository.countByStatus(UserStatus.ACTIVE)).thenReturn(80L);
            when(userRepository.countByStatus(UserStatus.INACTIVE)).thenReturn(15L);
            when(userRepository.countByStatus(UserStatus.SUSPENDED)).thenReturn(5L);
            when(userRepository.countByIsBiometricEnrolled(true)).thenReturn(50L);
            when(userRepository.sumVerificationCount()).thenReturn(1000L);

            // When
            StatisticsResponse response = getStatisticsService.execute();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getTotalUsers()).isEqualTo(100L);
            assertThat(response.getActiveUsers()).isEqualTo(80L);
            assertThat(response.getInactiveUsers()).isEqualTo(15L);
            assertThat(response.getSuspendedUsers()).isEqualTo(5L);
            assertThat(response.getBiometricEnrolledUsers()).isEqualTo(50L);
            assertThat(response.getTotalVerifications()).isEqualTo(1000L);

            verify(userRepository).count();
            verify(userRepository).countByStatus(UserStatus.ACTIVE);
            verify(userRepository).countByStatus(UserStatus.INACTIVE);
            verify(userRepository).countByStatus(UserStatus.SUSPENDED);
            verify(userRepository).countByIsBiometricEnrolled(true);
            verify(userRepository).sumVerificationCount();
        }

        @Test
        @DisplayName("Should return zero values for empty database")
        void shouldReturnZeroValuesForEmptyDatabase() {
            // Given
            when(userRepository.count()).thenReturn(0L);
            when(userRepository.countByStatus(UserStatus.ACTIVE)).thenReturn(0L);
            when(userRepository.countByStatus(UserStatus.INACTIVE)).thenReturn(0L);
            when(userRepository.countByStatus(UserStatus.SUSPENDED)).thenReturn(0L);
            when(userRepository.countByIsBiometricEnrolled(true)).thenReturn(0L);
            when(userRepository.sumVerificationCount()).thenReturn(null);

            // When
            StatisticsResponse response = getStatisticsService.execute();

            // Then
            assertThat(response.getTotalUsers()).isEqualTo(0L);
            assertThat(response.getActiveUsers()).isEqualTo(0L);
            assertThat(response.getInactiveUsers()).isEqualTo(0L);
            assertThat(response.getSuspendedUsers()).isEqualTo(0L);
            assertThat(response.getBiometricEnrolledUsers()).isEqualTo(0L);
            assertThat(response.getTotalVerifications()).isEqualTo(0L);
        }

        @Test
        @DisplayName("Should handle null sum verification count")
        void shouldHandleNullSumVerificationCount() {
            // Given
            when(userRepository.count()).thenReturn(10L);
            when(userRepository.countByStatus(UserStatus.ACTIVE)).thenReturn(10L);
            when(userRepository.countByStatus(UserStatus.INACTIVE)).thenReturn(0L);
            when(userRepository.countByStatus(UserStatus.SUSPENDED)).thenReturn(0L);
            when(userRepository.countByIsBiometricEnrolled(true)).thenReturn(0L);
            when(userRepository.sumVerificationCount()).thenReturn(null);

            // When
            StatisticsResponse response = getStatisticsService.execute();

            // Then
            assertThat(response.getTotalVerifications()).isEqualTo(0L);
        }

        @Test
        @DisplayName("Should correctly calculate when all users are active")
        void shouldCorrectlyCalculateWhenAllUsersAreActive() {
            // Given
            when(userRepository.count()).thenReturn(50L);
            when(userRepository.countByStatus(UserStatus.ACTIVE)).thenReturn(50L);
            when(userRepository.countByStatus(UserStatus.INACTIVE)).thenReturn(0L);
            when(userRepository.countByStatus(UserStatus.SUSPENDED)).thenReturn(0L);
            when(userRepository.countByIsBiometricEnrolled(true)).thenReturn(25L);
            when(userRepository.sumVerificationCount()).thenReturn(500L);

            // When
            StatisticsResponse response = getStatisticsService.execute();

            // Then
            assertThat(response.getTotalUsers()).isEqualTo(50L);
            assertThat(response.getActiveUsers()).isEqualTo(50L);
            assertThat(response.getInactiveUsers()).isEqualTo(0L);
            assertThat(response.getSuspendedUsers()).isEqualTo(0L);
        }

        @Test
        @DisplayName("Should handle large numbers")
        void shouldHandleLargeNumbers() {
            // Given
            when(userRepository.count()).thenReturn(1_000_000L);
            when(userRepository.countByStatus(UserStatus.ACTIVE)).thenReturn(900_000L);
            when(userRepository.countByStatus(UserStatus.INACTIVE)).thenReturn(80_000L);
            when(userRepository.countByStatus(UserStatus.SUSPENDED)).thenReturn(20_000L);
            when(userRepository.countByIsBiometricEnrolled(true)).thenReturn(500_000L);
            when(userRepository.sumVerificationCount()).thenReturn(10_000_000L);

            // When
            StatisticsResponse response = getStatisticsService.execute();

            // Then
            assertThat(response.getTotalUsers()).isEqualTo(1_000_000L);
            assertThat(response.getActiveUsers()).isEqualTo(900_000L);
            assertThat(response.getInactiveUsers()).isEqualTo(80_000L);
            assertThat(response.getSuspendedUsers()).isEqualTo(20_000L);
            assertThat(response.getBiometricEnrolledUsers()).isEqualTo(500_000L);
            assertThat(response.getTotalVerifications()).isEqualTo(10_000_000L);
        }
    }

    @Nested
    @DisplayName("Repository Interactions")
    class RepositoryInteractions {

        @Test
        @DisplayName("Should call all repository methods exactly once")
        void shouldCallAllRepositoryMethodsExactlyOnce() {
            // Given
            when(userRepository.count()).thenReturn(0L);
            when(userRepository.countByStatus(any())).thenReturn(0L);
            when(userRepository.countByIsBiometricEnrolled(anyBoolean())).thenReturn(0L);
            when(userRepository.sumVerificationCount()).thenReturn(0L);

            // When
            getStatisticsService.execute();

            // Then
            verify(userRepository, times(1)).count();
            verify(userRepository, times(1)).countByStatus(UserStatus.ACTIVE);
            verify(userRepository, times(1)).countByStatus(UserStatus.INACTIVE);
            verify(userRepository, times(1)).countByStatus(UserStatus.SUSPENDED);
            verify(userRepository, times(1)).countByIsBiometricEnrolled(true);
            verify(userRepository, times(1)).sumVerificationCount();
        }
    }
}
