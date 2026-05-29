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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.lenient;
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
        // saveAuditLogWithTenant nulls user_id when the id isn't a real user
        // (FK-resilience, 2026-05-29). These tests' random user ids represent
        // existing users, so stub existsById=true; lenient() because
        // anonymous/null-user events never reach the check.
        lenient().when(userRepository.existsById(any())).thenReturn(true);
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
    @DisplayName("Tenant-management events separate actor (user_id) from resource (tenant) [P1-4]")
    class TenantManagementEvents {

        @Test
        @DisplayName("actor IS a real user → user_id set; resource_id and tenant_id = managed tenant; resourceType=TENANT")
        void realActorStampsUserIdAndResourceTenant() {
            UUID actorId = UUID.randomUUID();
            UUID managedTenantId = UUID.randomUUID();
            // existsById is already stubbed lenient(true) in setUp; the actor is a real user.

            adapter.logTenantManagementEvent(actorId.toString(), "TENANT_CREATED",
                    managedTenantId.toString(), "Tenant 'Acme' (slug=acme) created");

            AuditLog saved = captureSaved();
            assertThat(saved.getUserId()).isEqualTo(actorId);            // actor → user_id FK
            assertThat(saved.getResourceId()).isEqualTo(managedTenantId); // tenant → resource_id
            assertThat(saved.getTenantId()).isEqualTo(managedTenantId);   // tenant → tenant_id (managed tenant)
            assertThat(saved.getResourceType()).isEqualTo("TENANT");
            assertThat(saved.getAction()).isEqualTo("TENANT_CREATED");
            assertThat(saved.getSuccess()).isTrue();
            // details is HTML-escaped on the way in (defense-in-depth) — the
            // apostrophes become &#39; per the AuditEscape contract.
            assertThat(saved.getMetadata())
                    .containsEntry("details", "Tenant &#39;Acme&#39; (slug=acme) created");
            // tenant_id is supplied pre-resolved → no user-based tenant lookup.
            verify(userRepository, never()).findTenantIdById(any());
        }

        @Test
        @DisplayName("actor is null (self-service onboarding) → user_id null; resource/tenant still the managed tenant")
        void nullActorLeavesUserIdNull() {
            UUID managedTenantId = UUID.randomUUID();

            adapter.logTenantManagementEvent(null, "TENANT_CREATED",
                    managedTenantId.toString(), "Self-service tenant");

            AuditLog saved = captureSaved();
            assertThat(saved.getUserId()).isNull();
            assertThat(saved.getResourceId()).isEqualTo(managedTenantId);
            assertThat(saved.getTenantId()).isEqualTo(managedTenantId);
            assertThat(saved.getResourceType()).isEqualTo("TENANT");
            // existsById must never be consulted for a null actor.
            verify(userRepository, never()).existsById(any());
        }

        @Test
        @DisplayName("actor is a non-existent user → user_id null (FK guard); resource/tenant unchanged")
        void nonExistentActorIsNulledByFkGuard() {
            UUID ghostActorId = UUID.randomUUID();
            UUID managedTenantId = UUID.randomUUID();
            // Override the lenient default: this actor is NOT a real user row.
            when(userRepository.existsById(ghostActorId)).thenReturn(false);

            adapter.logTenantManagementEvent(ghostActorId.toString(), "TENANT_UPDATED",
                    managedTenantId.toString(), "ghost edit");

            AuditLog saved = captureSaved();
            assertThat(saved.getUserId()).isNull();                       // FK guard nulled it
            assertThat(saved.getResourceId()).isEqualTo(managedTenantId); // resource preserved
            assertThat(saved.getTenantId()).isEqualTo(managedTenantId);
            assertThat(saved.getAction()).isEqualTo("TENANT_UPDATED");
        }

        @Test
        @DisplayName("null details → empty metadata, row still saved")
        void nullDetailsEmptyMetadata() {
            UUID actorId = UUID.randomUUID();
            UUID managedTenantId = UUID.randomUUID();

            adapter.logTenantManagementEvent(actorId.toString(), "TENANT_DELETED",
                    managedTenantId.toString(), null);

            AuditLog saved = captureSaved();
            assertThat(saved.getMetadata()).isEmpty();
            assertThat(saved.getResourceId()).isEqualTo(managedTenantId);
        }

        @Test
        @DisplayName("HTML in details is escaped on the way in")
        void detailsAreEscaped() {
            UUID actorId = UUID.randomUUID();
            UUID managedTenantId = UUID.randomUUID();

            adapter.logTenantManagementEvent(actorId.toString(), "TENANT_UPDATED",
                    managedTenantId.toString(), "<script>alert(1)</script>");

            AuditLog saved = captureSaved();
            assertThat(saved.getMetadata())
                    .containsEntry("details", "&lt;script&gt;alert(1)&lt;/script&gt;");
        }

        @Test
        @DisplayName("malformed tenant id → resource_id null but row still saved (no whole-row drop)")
        void malformedTenantIdNullsResourceButSaves() {
            UUID actorId = UUID.randomUUID();

            adapter.logTenantManagementEvent(actorId.toString(), "TENANT_UPDATED",
                    "not-a-uuid", "bad id");

            AuditLog saved = captureSaved();
            assertThat(saved.getResourceId()).isNull();
            // tenant_id pre-resolution also fails to parse → falls back to the
            // actor's tenant lookup. Actor is a real user (lenient existsById=true)
            // but findTenantIdById is unstubbed → Optional.empty → SYSTEM sentinel.
            assertThat(saved.getTenantId()).isEqualTo(AuditLogAdapter.SYSTEM_TENANT_ID);
            assertThat(saved.getAction()).isEqualTo("TENANT_UPDATED");
        }
    }

    @Nested
    @DisplayName("System / anonymous events stamp tenant_id with the SYSTEM_TENANT_ID sentinel [T4-C]")
    class SystemEvents {

        @Test
        @DisplayName("logAuthenticationFailed (unknown email) stamps SYSTEM_TENANT_ID sentinel")
        void anonymousFailedLoginUsesSentinel() {
            // No user is known yet — failed login pre-resolution, email
            // does not match any tenant user.
            when(userRepository.findByEmail("attacker@example.com"))
                    .thenReturn(Optional.empty());

            adapter.logAuthenticationFailed("attacker@example.com", "1.2.3.4",
                    "Invalid credentials");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(AuditLogAdapter.SYSTEM_TENANT_ID);
            assertThat(saved.getUserId()).isNull();
            assertThat(saved.getAction()).isEqualTo("FAILED_LOGIN_ATTEMPT");
            verify(userRepository, never()).findTenantIdById(any());
        }

        @Test
        @DisplayName("logAuthenticationFailed: known email routes audit row to that user's tenant")
        void failedLoginWithKnownEmailUsesTenantOfUser() {
            // Targeted account: the user exists but the password was wrong.
            // We must stamp the row with that user's tenant so the tenant
            // admin sees the attack attempt.
            com.fivucsas.identity.entity.User u = mock(com.fivucsas.identity.entity.User.class);
            when(u.getTenantId())
                    .thenReturn(com.fivucsas.identity.domain.model.tenant.TenantId.of(tenantId));
            when(userRepository.findByEmail("victim@example.com"))
                    .thenReturn(Optional.of(u));

            adapter.logAuthenticationFailed("victim@example.com", "1.2.3.4",
                    "Invalid credentials");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(tenantId);
            assertThat(saved.getUserId()).isNull();
            assertThat(saved.getAction()).isEqualTo("FAILED_LOGIN_ATTEMPT");
        }

        @Test
        @DisplayName("logPkceFailure (no userId) stamps SYSTEM_TENANT_ID sentinel")
        void pkceFailureUsesSentinel() {
            adapter.logPkceFailure("client-x", "1.2.3.4", "VERIFIER_MISMATCH");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(AuditLogAdapter.SYSTEM_TENANT_ID);
        }
    }

    @Nested
    @DisplayName("Resilience: tenant resolution must never fail an audit write")
    class Resilience {

        @Test
        @DisplayName("Missing user record stamps SYSTEM_TENANT_ID sentinel but still saves the row [T4-C]")
        void missingUserRecordStillSaves() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.empty());

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(AuditLogAdapter.SYSTEM_TENANT_ID);
            assertThat(saved.getUserId()).isEqualTo(userId);
        }

        @Test
        @DisplayName("Repository throwing on lookup stamps SYSTEM_TENANT_ID sentinel but still saves [T4-C]")
        void repositoryThrowingStillSaves() {
            when(userRepository.findTenantIdById(userId))
                    .thenThrow(new RuntimeException("transient db error"));

            adapter.logUserAuthenticated(userId.toString(), "u@example.com",
                    "1.2.3.4", "Mozilla/5.0");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(AuditLogAdapter.SYSTEM_TENANT_ID);
        }

        @Test
        @DisplayName("logAuthenticationFailed: email-resolution failure falls through to sentinel [T4-C]")
        void failedLoginEmailLookupThrowingFallsToSentinel() {
            when(userRepository.findByEmail("victim@example.com"))
                    .thenThrow(new RuntimeException("transient db error"));

            adapter.logAuthenticationFailed("victim@example.com", "1.2.3.4",
                    "Invalid credentials");

            AuditLog saved = captureSaved();
            assertThat(saved.getTenantId()).isEqualTo(AuditLogAdapter.SYSTEM_TENANT_ID);
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

        /**
         * SECURITY_REVIEW_2026-05-01 §P2-1: action and resourceType are
         * static literals at every current call site, but escape coverage
         * is uniform — the next caller wiring tenant-supplied event types
         * must inherit the escape automatically.
         */
        @Test
        @DisplayName("logSecurityEvent: action and resourceType are escaped on the way in")
        void actionAndResourceTypeAreEscaped() {
            when(userRepository.findTenantIdById(userId)).thenReturn(Optional.of(tenantId));

            // Pass an attacker-shaped eventType; logSecurityEvent threads it
            // straight into AuditLog.action.
            adapter.logSecurityEvent(userId.toString(), "<script>alert(1)</script>",
                    "1.2.3.4", "details");

            AuditLog saved = captureSaved();
            assertThat(saved.getAction())
                    .isEqualTo("&lt;script&gt;alert(1)&lt;/script&gt;");
            // resourceType is hard-coded to "SECURITY"; assert it round-trips
            // unchanged (no special chars to escape).
            assertThat(saved.getResourceType()).isEqualTo("SECURITY");
        }
    }

    @Nested
    @DisplayName("§P2-1 sweep: every direct AuditLog.builder call site honors the escape contract")
    class DirectWriteSweep {

        /**
         * Defense-in-depth regression: walk one direct-call path
         * (logPkceFailure — the most exposed because clientId can be any
         * caller-supplied string) and assert the row never carries raw HTML
         * even when the input does. Mirrors the aspect's escape contract.
         */
        @Test
        @DisplayName("PKCE failure with HTML in clientId: row is sanitized end-to-end")
        void pkceFailureSanitizesAllStringFields() {
            adapter.logPkceFailure("<x onerror=alert(1)>", "1.2.3.4",
                    "VERIFIER_MISMATCH");

            AuditLog saved = captureSaved();
            // action / resourceType are literals on this method; verify both
            // round-trip and that no raw HTML leaks via metadata.clientId.
            assertThat(saved.getAction()).isEqualTo("PKCE_FAILURE");
            assertThat(saved.getResourceType()).isEqualTo("OAUTH2");
            assertThat(saved.getMetadata())
                    .containsEntry("clientId", "&lt;x onerror=alert(1)&gt;");
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
