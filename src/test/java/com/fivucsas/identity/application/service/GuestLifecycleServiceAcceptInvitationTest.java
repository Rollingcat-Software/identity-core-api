package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.domain.exception.TenantSuspendedException;
import com.fivucsas.identity.domain.exception.TenantUserQuotaExceededException;
import com.fivucsas.identity.domain.repository.RefreshTokenRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.InvitationStatus;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.exception.DomainStateConflictException;
import com.fivucsas.identity.infrastructure.email.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the P1-9 hardening of
 * {@link GuestLifecycleService#acceptInvitation(String, String, String, String)}:
 * the accept path now enforces the tenant {@code max_users} quota, rejects a
 * SUSPENDED / INACTIVE tenant, and scopes the existing-email check to the
 * invitation's tenant.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("GuestLifecycleService.acceptInvitation (P1-9 gates)")
class GuestLifecycleServiceAcceptInvitationTest {

    @Mock private GuestInvitationRepositoryPort invitationRepository;
    @Mock private UserRepository userRepository;
    @Mock private UserRoleRepositoryPort userRoleRepository;
    @Mock private RoleRepositoryPort roleRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private EmailService emailService;
    @Mock private AuditLogPort auditLogPort;

    private GuestLifecycleService service;

    private static final String TOKEN = "invite-tok";
    private static final String EMAIL = "guest@example.com";
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        service = new GuestLifecycleService(
                invitationRepository, userRepository, userRoleRepository,
                roleRepository, refreshTokenRepository, passwordEncoder,
                emailService, auditLogPort);
        tenantId = UUID.randomUUID();
    }

    private GuestInvitation pendingInvitation(TenantStatus tenantStatus, int maxUsers) {
        Tenant tenant = Tenant.builder()
                .id(tenantId)
                .name("Marmara University")
                .status(tenantStatus)
                .maxUsers(maxUsers)
                .build();
        Instant now = Instant.now();
        return GuestInvitation.builder()
                .id(UUID.randomUUID())
                .tenant(tenant)
                .email(EMAIL)
                .invitedBy(User.builder().id(UUID.randomUUID()).email("admin@tenant.example").build())
                .status(InvitationStatus.PENDING)
                .invitationToken(TOKEN)
                .expiresAt(now.plus(24, ChronoUnit.HOURS))
                .accessStartsAt(now)
                .accessEndsAt(now.plus(24, ChronoUnit.HOURS))
                .build();
    }

    @Test
    @DisplayName("happy path → creates the guest user when tenant ACTIVE, under quota, email free")
    void acceptsWhenAllGatesPass() {
        GuestInvitation inv = pendingInvitation(TenantStatus.ACTIVE, 100);
        when(invitationRepository.findByInvitationToken(TOKEN)).thenReturn(Optional.of(inv));
        when(userRepository.countByTenantId(tenantId)).thenReturn(5L);
        when(userRepository.existsByEmailAndTenantId(EMAIL, tenantId)).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));
        lenient().when(roleRepository.findById(any())).thenReturn(Optional.empty());

        User created = service.acceptInvitation(TOKEN, "Guest", "User", "pw");

        assertThat(created.getEmail()).isEqualTo(EMAIL);
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("SUSPENDED tenant → TenantSuspendedException, no user created")
    void rejectsSuspendedTenant() {
        GuestInvitation inv = pendingInvitation(TenantStatus.SUSPENDED, 100);
        when(invitationRepository.findByInvitationToken(TOKEN)).thenReturn(Optional.of(inv));

        assertThatThrownBy(() -> service.acceptInvitation(TOKEN, "Guest", "User", "pw"))
                .isInstanceOf(TenantSuspendedException.class);

        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(any());
    }

    @Test
    @DisplayName("tenant at max_users → TenantUserQuotaExceededException, no user created")
    void rejectsWhenQuotaExceeded() {
        GuestInvitation inv = pendingInvitation(TenantStatus.ACTIVE, 10);
        when(invitationRepository.findByInvitationToken(TOKEN)).thenReturn(Optional.of(inv));
        when(userRepository.countByTenantId(tenantId)).thenReturn(10L); // == cap

        assertThatThrownBy(() -> service.acceptInvitation(TOKEN, "Guest", "User", "pw"))
                .isInstanceOf(TenantUserQuotaExceededException.class);

        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(any());
    }

    @Test
    @DisplayName("email already in THIS tenant → 409 conflict, no user created")
    void rejectsDuplicateEmailInTenant() {
        GuestInvitation inv = pendingInvitation(TenantStatus.ACTIVE, 100);
        when(invitationRepository.findByInvitationToken(TOKEN)).thenReturn(Optional.of(inv));
        when(userRepository.countByTenantId(tenantId)).thenReturn(1L);
        when(userRepository.existsByEmailAndTenantId(EMAIL, tenantId)).thenReturn(true);

        assertThatThrownBy(() -> service.acceptInvitation(TOKEN, "Guest", "User", "pw"))
                .isInstanceOf(DomainStateConflictException.class);

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("existing-email check is TENANT-SCOPED, not global (account-linking allows same email cross-tenant)")
    void existingEmailCheckIsTenantScoped() {
        GuestInvitation inv = pendingInvitation(TenantStatus.ACTIVE, 100);
        when(invitationRepository.findByInvitationToken(TOKEN)).thenReturn(Optional.of(inv));
        when(userRepository.countByTenantId(tenantId)).thenReturn(1L);
        when(userRepository.existsByEmailAndTenantId(EMAIL, tenantId)).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("hashed");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));
        lenient().when(roleRepository.findById(any())).thenReturn(Optional.empty());

        service.acceptInvitation(TOKEN, "Guest", "User", "pw");

        // The accept must consult the tenant-scoped check, never the global existsByEmail.
        verify(userRepository).existsByEmailAndTenantId(EMAIL, tenantId);
        verify(userRepository, never()).existsByEmail(any());
    }
}
