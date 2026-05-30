package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.domain.repository.RefreshTokenRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.email.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link GuestLifecycleService#createInvitation} — the invitation
 * email MUST be dispatched (WS5: invited guests previously never got the accept
 * link) and the recipient's tenant name + locale MUST be threaded through.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("GuestLifecycleService.createInvitation — email dispatch + i18n threading")
class GuestLifecycleServiceCreateInvitationEmailTest {

    @Mock private GuestInvitationRepositoryPort invitationRepository;
    @Mock private UserRepository userRepository;
    @Mock private UserRoleRepositoryPort userRoleRepository;
    @Mock private RoleRepositoryPort roleRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private EmailService emailService;
    @Mock private AuditLogPort auditLogPort;

    private GuestLifecycleService service;

    private Tenant tenant;
    private User inviter;

    @BeforeEach
    void setUp() {
        service = new GuestLifecycleService(
                invitationRepository, userRepository, userRoleRepository,
                roleRepository, refreshTokenRepository, passwordEncoder,
                emailService, auditLogPort);

        tenant = Tenant.builder().id(UUID.randomUUID()).name("Marmara University").build();
        inviter = User.builder().id(UUID.randomUUID()).email("admin@marmara.edu.tr").build();

        // save(...) returns the entity it was handed.
        when(invitationRepository.existsActiveInvitation(any(), anyString())).thenReturn(false);
        when(invitationRepository.save(any(GuestInvitation.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("dispatches the invitation email with tenant name + Turkish locale")
    void dispatchesEmailWithTenantAndLocale() {
        service.createInvitation(tenant, "guest@example.com", inviter, 24,
                "welcome", "Admin Adam", "tr");

        verify(emailService).sendGuestInvitation(
                eq("guest@example.com"),
                anyString(),                 // token
                any(Instant.class),          // accessStart
                any(Instant.class),          // accessEnd
                eq("welcome"),               // message
                eq("Admin Adam"),            // inviterName
                eq("Marmara University"),    // tenantName
                eq("tr"));                   // locale
    }

    @Test
    @DisplayName("null locale is threaded through (EN fallback happens in the email layer)")
    void nullLocaleThreaded() {
        service.createInvitation(tenant, "guest@example.com", inviter, 24,
                null, "Admin Adam", null);

        verify(emailService).sendGuestInvitation(
                eq("guest@example.com"),
                anyString(),
                any(Instant.class),
                any(Instant.class),
                isNull(),
                eq("Admin Adam"),
                eq("Marmara University"),
                isNull());
    }

    @Test
    @DisplayName("an email failure does NOT abort invitation creation (admin can resend)")
    void emailFailureDoesNotAbort() {
        org.mockito.Mockito.doThrow(new RuntimeException("smtp down"))
                .when(emailService).sendGuestInvitation(
                        anyString(), anyString(), any(), any(), any(), any(), any(), any());

        // Should not throw — invitation persistence is authoritative.
        GuestInvitation result = service.createInvitation(tenant, "guest@example.com", inviter, 24,
                null, "Admin Adam", "en");

        org.assertj.core.api.Assertions.assertThat(result).isNotNull();
        verify(invitationRepository).save(any(GuestInvitation.class));
    }

    @Test
    @DisplayName("3-arg overload still dispatches email (back-compat) with null tenant-aware extras")
    void backCompatOverloadDispatches() {
        service.createInvitation(tenant, "guest@example.com", inviter, 24, "msg");

        verify(emailService).sendGuestInvitation(
                eq("guest@example.com"),
                anyString(), any(Instant.class), any(Instant.class),
                eq("msg"),
                isNull(),                    // inviterName
                eq("Marmara University"),    // tenantName from the tenant
                isNull());                   // locale
        verify(emailService, never()).sendOtp(any(), any());
    }
}
