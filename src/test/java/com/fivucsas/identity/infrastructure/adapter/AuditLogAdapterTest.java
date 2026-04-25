package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.entity.AuditLog;
import com.fivucsas.identity.repository.AuditLogRepository;
import com.fivucsas.identity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link AuditLogAdapter} focused on the {@code tenant_id}
 * population guarantee.
 *
 * <p>Background: tenant-admin's {@code GET /api/v1/audit-logs} endpoint filters
 * rows by {@code tenant_id = X}. Prior to the 2026-04-25 fix the writer never
 * set {@code tenant_id}, so almost every audit row was invisible to admins.
 * These tests pin the writer's contract: any user-scoped audit row MUST stamp
 * the tenant resolved from the user's record.</p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditLogAdapter — tenant_id population")
class AuditLogAdapterTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuditLogAdapter adapter;

    private UUID userId;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
    }

    @Nested
    @DisplayName("User-scoped events resolve tenant_id from the user record")
    class UserScopedEvents {

        @Test
        @DisplayName("logUserAuthenticated stamps tenant_id from user lookup")
        void logUserAuthenticatedStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getUserId()).isEqualTo(userId);
            assertThat(saved.getAction()).isEqualTo("USER_LOGIN");
            assertThat(saved.getSuccess()).isTrue();
        }

        @Test
        @DisplayName("logUserAuthenticated (oauth overload) stamps tenant_id")
        void logUserAuthenticatedOauthStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "Mozilla/5.0", "Marmara BYS");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getMetadata()).containsEntry("oauthClient", "Marmara BYS");
        }

        @Test
        @DisplayName("logUserRegistered stamps tenant_id")
        void logUserRegisteredStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logUserRegistered(userId.toString(), "u@example.com", "1.2.3.4");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getAction()).isEqualTo("USER_CREATED");
        }

        @Test
        @DisplayName("logUserLoggedOut stamps tenant_id")
        void logUserLoggedOutStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logUserLoggedOut(userId.toString(), "u@example.com");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getAction()).isEqualTo("USER_LOGOUT");
        }

        @Test
        @DisplayName("logSecurityEvent stamps tenant_id")
        void logSecurityEventStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logSecurityEvent(userId.toString(), "PASSWORD_CHANGED",
                    "1.2.3.4", "self-service");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getAction()).isEqualTo("PASSWORD_CHANGED");
        }

        @Test
        @DisplayName("logBiometricEnrollment stamps tenant_id")
        void logBiometricEnrollmentStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logBiometricEnrollment(userId.toString(), true);

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getResourceType()).isEqualTo("BIOMETRIC");
        }

        @Test
        @DisplayName("logBiometricVerification stamps tenant_id")
        void logBiometricVerificationStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logBiometricVerification(userId.toString(), false);

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getSuccess()).isFalse();
        }

        @Test
        @DisplayName("logMfaStepCompleted stamps tenant_id")
        void logMfaStepCompletedStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logMfaStepCompleted(userId.toString(), "FACE", 2, 3,
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getMetadata())
                    .containsEntry("method", "FACE")
                    .containsEntry("stepCurrent", 2)
                    .containsEntry("stepTotal", 3);
        }

        @Test
        @DisplayName("logMfaComplete stamps tenant_id")
        void logMfaCompleteStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logMfaComplete(userId.toString(), List.of("pwd", "sms"),
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getAction()).isEqualTo("MFA_COMPLETE");
        }

        @Test
        @DisplayName("logTwoFactorVerified stamps tenant_id")
        void logTwoFactorVerifiedStampsTenantId() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logTwoFactorVerified(userId.toString(), "TOTP",
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
        }
    }

    @Nested
    @DisplayName("System / anonymous events leave tenant_id NULL")
    class SystemEvents {

        @Test
        @DisplayName("logAuthenticationFailed (anonymous) leaves tenant_id NULL")
        void anonymousFailedLoginIsCrossTenant() {
            // No user is known yet — failed login pre-resolution.
            adapter.logAuthenticationFailed("attacker@example.com", "1.2.3.4",
                    "Invalid credentials");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isNull();
            assertThat(saved.getUserId()).isNull();
            assertThat(saved.getAction()).isEqualTo("FAILED_LOGIN_ATTEMPT");
            verify(userRepository, never()).findTenantIdById(any());
        }
    }

    @Nested
    @DisplayName("Resilience: tenant resolution must never fail an audit write")
    class Resilience {

        @Test
        @DisplayName("Missing user record leaves tenant_id NULL but still saves the row")
        void missingUserRecordStillSaves() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.empty());

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isNull();
            assertThat(saved.getUserId()).isEqualTo(userId);
        }

        @Test
        @DisplayName("Repository throwing on lookup leaves tenant_id NULL but still saves")
        void repositoryThrowingStillSaves() {
            when(userRepository.findTenantIdById(userId))
                    .thenThrow(new RuntimeException("transient db error"));

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isNull();
        }
    }

    private AuditLog captureSaved() {
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        return captor.getValue();
    }
}
