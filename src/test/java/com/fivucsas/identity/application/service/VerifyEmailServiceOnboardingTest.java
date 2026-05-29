package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.VerifyEmailCommand;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.TenantProvisioningPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.entity.UserType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("VerifyEmailService — onboarding tenant-activation hook")
class VerifyEmailServiceOnboardingTest {

    @Mock private UserRepository userRepository;
    @Mock private AuditLogPort auditLogPort;
    @Mock private TenantProvisioningPort tenantProvisioningPort;

    @InjectMocks private VerifyEmailService service;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "requireAdminApproval", false);
    }

    private User adminUserWithToken(UUID id, String token) {
        User user = User.builder()
                .id(id)
                .email("admin@acme.example")
                .firstName("Ada")
                .lastName("Lovelace")
                .userType(UserType.TENANT_ADMIN)
                .emailVerified(false)
                .build();
        // Set the verification token + sent-at so verifyEmail(token) succeeds
        // and the token is not considered expired.
        ReflectionTestUtils.setField(user, "emailVerificationToken", token);
        ReflectionTestUtils.setField(user, "emailVerificationSentAt", java.time.Instant.now());
        return user;
    }

    @Test
    @DisplayName("TENANT_ADMIN verifies email → tenant activated, PENDING→ACTIVE event")
    void tenantAdminActivatesTenant() {
        UUID userId = UUID.randomUUID();
        User admin = adminUserWithToken(userId, "tok-123");
        when(userRepository.findByEmailVerificationToken("tok-123")).thenReturn(Optional.of(admin));
        when(tenantProvisioningPort.activateTenantForVerifiedAdmin(userId, false)).thenReturn(true);

        service.execute(VerifyEmailCommand.builder().token("tok-123").ipAddress("203.0.113.7").build());

        verify(userRepository).save(admin);
        verify(tenantProvisioningPort).activateTenantForVerifiedAdmin(userId, false);
        verify(auditLogPort).logSecurityEvent(
                eq(userId.toString()), eq("EMAIL_VERIFIED"), anyString(), anyString());
        verify(auditLogPort).logSecurityEvent(
                eq(userId.toString()), eq("TENANT_ACTIVATED_ON_VERIFICATION"), anyString(), anyString());
    }

    @Test
    @DisplayName("require-admin-approval → verified but tenant stays PENDING")
    void tenantStaysPendingWhenApprovalRequired() {
        ReflectionTestUtils.setField(service, "requireAdminApproval", true);
        UUID userId = UUID.randomUUID();
        User admin = adminUserWithToken(userId, "tok-456");
        when(userRepository.findByEmailVerificationToken("tok-456")).thenReturn(Optional.of(admin));
        when(tenantProvisioningPort.activateTenantForVerifiedAdmin(userId, true)).thenReturn(false);

        service.execute(VerifyEmailCommand.builder().token("tok-456").build());

        verify(tenantProvisioningPort).activateTenantForVerifiedAdmin(userId, true);
        verify(auditLogPort).logSecurityEvent(
                eq(userId.toString()), eq("TENANT_PENDING_ADMIN_APPROVAL"), any(), anyString());
    }

    @Test
    @DisplayName("non-admin user verifying email does NOT touch tenant activation")
    void nonAdminDoesNotActivateTenant() {
        UUID userId = UUID.randomUUID();
        User member = adminUserWithToken(userId, "tok-789");
        member.setUserType(UserType.TENANT_MEMBER);
        when(userRepository.findByEmailVerificationToken("tok-789")).thenReturn(Optional.of(member));

        service.execute(VerifyEmailCommand.builder().token("tok-789").build());

        verify(tenantProvisioningPort, never()).activateTenantForVerifiedAdmin(any(), anyBoolean());
    }
}
