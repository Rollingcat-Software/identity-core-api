package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.StatisticsResponse;
import com.fivucsas.identity.domain.model.user.UserStatus;
import com.fivucsas.identity.domain.repository.TenantRepository;
import com.fivucsas.identity.application.port.output.AuditLogQueryPort;
import com.fivucsas.identity.domain.repository.UserDomainRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("GetStatisticsService Tests")
class GetStatisticsServiceTest {

    @Mock
    private UserDomainRepository userRepository;

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private AuditLogQueryPort auditLogRepository;

    @InjectMocks
    private GetStatisticsService getStatisticsService;

    @BeforeEach
    void setUp() {
        // Mock tenantRepository.count() - service calls this outside try/catch
        lenient().when(tenantRepository.count()).thenReturn(0L);
        // Mock auditLogRepository - service calls these in try/catch but let's provide proper mocks
        @SuppressWarnings("unchecked")
        Page<com.fivucsas.identity.entity.AuditLog> emptyPage = mock(Page.class);
        lenient().when(emptyPage.getTotalElements()).thenReturn(0L);
        lenient().when(auditLogRepository.findBySuccessOrderByCreatedAtDesc(any(), any())).thenReturn(emptyPage);
    }

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
        @DisplayName("verificationSuccessRate is NOT a fabricated 100% when verifications exist but no real failure data")
        void verificationSuccessRateIsNotFabricated100() {
            // Given a populated system with verifications but no real
            // verification-failure source (failedEnrollments has none).
            when(userRepository.count()).thenReturn(100L);
            when(userRepository.countByStatus(UserStatus.ACTIVE)).thenReturn(100L);
            when(userRepository.countByStatus(UserStatus.INACTIVE)).thenReturn(0L);
            when(userRepository.countByStatus(UserStatus.SUSPENDED)).thenReturn(0L);
            when(userRepository.countByIsBiometricEnrolled(true)).thenReturn(50L);
            when(userRepository.sumVerificationCount()).thenReturn(1000L);

            // When
            StatisticsResponse response = getStatisticsService.execute();

            // Then — the old bug computed 1000/(1000+0)=100.0 always; the honest
            // fix reports 0.0 ("not tracked") rather than a misleading 100%.
            assertThat(response.getVerificationSuccessRate())
                    .as("verification success rate must not be a fake 100%")
                    .isNotEqualTo(100.0);
            assertThat(response.getVerificationSuccessRate()).isEqualTo(0.0);
            // Raw counts stay truthful.
            assertThat(response.getTotalVerifications()).isEqualTo(1000L);
            assertThat(response.getFailedEnrollments()).isEqualTo(0L);
            assertThat(response.getSuccessfulEnrollments()).isEqualTo(50L);
        }

        @Test
        @DisplayName("authSuccessRate IS computed from real audit success/failure counts")
        void authSuccessRateFromRealAuditCounts() {
            when(userRepository.count()).thenReturn(10L);
            when(userRepository.countByStatus(any())).thenReturn(0L);
            when(userRepository.countByIsBiometricEnrolled(true)).thenReturn(0L);
            when(userRepository.sumVerificationCount()).thenReturn(0L);

            // 80 success, 20 failed → 80.0% (rounded to 1 dp).
            @SuppressWarnings("unchecked")
            Page<com.fivucsas.identity.entity.AuditLog> successPage = mock(Page.class);
            @SuppressWarnings("unchecked")
            Page<com.fivucsas.identity.entity.AuditLog> failedPage = mock(Page.class);
            when(successPage.getTotalElements()).thenReturn(80L);
            when(failedPage.getTotalElements()).thenReturn(20L);
            when(auditLogRepository.findBySuccessOrderByCreatedAtDesc(eq(true), any())).thenReturn(successPage);
            when(auditLogRepository.findBySuccessOrderByCreatedAtDesc(eq(false), any())).thenReturn(failedPage);

            StatisticsResponse response = getStatisticsService.execute();

            assertThat(response.getAuthSuccessRate()).isEqualTo(80.0);
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
