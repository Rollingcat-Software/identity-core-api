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
import java.util.Map;
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

    @Nested
    @DisplayName("HTML escaping: defense-in-depth for user-supplied strings")
    class Escaping {

        @Test
        @DisplayName("HTML special chars in userAgent are escaped on write")
        void userAgentIsEscaped() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "<script>alert('xss')</script>");

            AuditLog saved = captureSaved();
            assertThat(saved.getUserAgent())
                    .isEqualTo("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
        }

        @Test
        @DisplayName("Null userAgent stays null (no NPE)")
        void nullUserAgentStaysNull() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", null);

            AuditLog saved = captureSaved();
            assertThat(saved.getUserAgent()).isNull();
        }

        @Test
        @DisplayName("String values in metadata are escaped")
        void stringMetadataValuesAreEscaped() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            // logUserAuthenticated(oauth) puts oauthClient into metadata as String.
            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "Mozilla/5.0", "<img src=x onerror=alert(1)>");

            AuditLog saved = captureSaved();
            assertThat(saved.getMetadata())
                    .containsEntry("oauthClient",
                            "&lt;img src=x onerror=alert(1)&gt;");
        }

        @Test
        @DisplayName("Non-String metadata values pass through unchanged")
        void nonStringMetadataValuesPassThrough() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            // logMfaStepCompleted has Integer values for stepCurrent / stepTotal
            // and String values for method.
            adapter.logMfaStepCompleted(userId.toString(), "FACE", 2, 3,
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            Map<String, Object> meta = saved.getMetadata();
            assertThat(meta.get("stepCurrent")).isEqualTo(2);
            assertThat(meta.get("stepTotal")).isEqualTo(3);
            assertThat(meta.get("method")).isEqualTo("FACE");
        }

        @Test
        @DisplayName("List metadata values pass through unchanged")
        void listMetadataValuesPassThrough() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            adapter.logMfaComplete(userId.toString(), List.of("pwd", "<sms>"),
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            // The List itself passes through unchanged — escapeIfString only
            // escapes top-level Strings. Per AuditEscape contract, structured
            // payloads keep their original type for JSONB storage.
            Object amr = saved.getMetadata().get("amr");
            assertThat(amr).isInstanceOf(List.class);
            @SuppressWarnings("unchecked")
            List<String> amrList = (List<String>) amr;
            assertThat(amrList).containsExactly("pwd", "<sms>");
        }

        @Test
        @DisplayName("PKCE failure: failureReason String is escaped")
        void pkceFailureReasonEscaped() {
            adapter.logPkceFailure("client-x", "1.2.3.4",
                    "<bad>code_verifier mismatch</bad>");

            AuditLog saved = captureSaved();
            assertThat(saved.getMetadata())
                    .containsEntry("failureReason",
                            "&lt;bad&gt;code_verifier mismatch&lt;/bad&gt;");
        }

        @Test
        @DisplayName("No special chars: userAgent passes through unchanged")
        void plainUserAgentPassesThrough() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            String plain = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";
            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", plain);

            AuditLog saved = captureSaved();
            assertThat(saved.getUserAgent()).isEqualTo(plain);
        }
    }

    private AuditLog captureSaved() {
        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        return captor.getValue();
    }
}
