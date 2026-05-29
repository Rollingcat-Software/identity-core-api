package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.domain.repository.RefreshTokenRepository;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.InvitationStatus;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.exception.DomainStateConflictException;
import com.fivucsas.identity.infrastructure.email.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link GuestLifecycleService#revokeInvitation(UUID, UUID)} —
 * cancelling a PENDING (un-accepted) guest invitation, which has no guest user
 * row yet so the user-revoke path cannot reach it.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("GuestLifecycleService.revokeInvitation")
class GuestLifecycleServiceRevokeInvitationTest {

    @Mock private GuestInvitationRepositoryPort invitationRepository;
    @Mock private UserRepository userRepository;
    @Mock private UserRoleRepositoryPort userRoleRepository;
    @Mock private RoleRepositoryPort roleRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private EmailService emailService;
    @Mock private AuditLogPort auditLogPort;

    private GuestLifecycleService service;

    private UUID invitationId;
    private UUID tenantId;
    private User actingAdmin;

    @BeforeEach
    void setUp() {
        service = new GuestLifecycleService(
                invitationRepository, userRepository, userRoleRepository,
                roleRepository, refreshTokenRepository, passwordEncoder,
                emailService, auditLogPort);

        invitationId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
        actingAdmin = User.builder().id(UUID.randomUUID()).email("admin@tenant.example").build();
    }

    private GuestInvitation invitationWithStatus(InvitationStatus status) {
        Tenant tenant = Tenant.builder().id(tenantId).build();
        Instant now = Instant.now();
        return GuestInvitation.builder()
                .id(invitationId)
                .tenant(tenant)
                .email("guest@example.com")
                .invitedBy(actingAdmin)
                .status(status)
                .invitationToken("tok")
                .expiresAt(now.plus(24, ChronoUnit.HOURS))
                .accessStartsAt(now)
                .accessEndsAt(now.plus(24, ChronoUnit.HOURS))
                .build();
    }

    @Test
    @DisplayName("PENDING invitation → set to REVOKED + audited with the acting admin's user id")
    void revokesPendingInvitation() {
        GuestInvitation pending = invitationWithStatus(InvitationStatus.PENDING);
        when(invitationRepository.findById(invitationId)).thenReturn(Optional.of(pending));

        service.revokeInvitation(invitationId, actingAdmin.getId());

        assertThat(pending.getStatus()).isEqualTo(InvitationStatus.REVOKED);
        assertThat(pending.getRevokedAt()).isNotNull();

        ArgumentCaptor<GuestInvitation> saved = ArgumentCaptor.forClass(GuestInvitation.class);
        verify(invitationRepository).save(saved.capture());
        assertThat(saved.getValue().getStatus()).isEqualTo(InvitationStatus.REVOKED);

        // Audit: userId is the acting admin's id — NEVER the invitation/tenant id.
        verify(auditLogPort).logSecurityEvent(
                eq(actingAdmin.getId().toString()),
                eq("GUEST_INVITATION_REVOKED"),
                isNull(),
                any(String.class));
    }

    @Test
    @DisplayName("EXPIRED invitation → set to REVOKED")
    void revokesExpiredInvitation() {
        GuestInvitation expired = invitationWithStatus(InvitationStatus.EXPIRED);
        when(invitationRepository.findById(invitationId)).thenReturn(Optional.of(expired));

        service.revokeInvitation(invitationId, actingAdmin.getId());

        assertThat(expired.getStatus()).isEqualTo(InvitationStatus.REVOKED);
        verify(invitationRepository).save(any(GuestInvitation.class));
    }

    @Test
    @DisplayName("Already REVOKED → idempotent no-op (no save, no audit)")
    void revokeIsIdempotent() {
        GuestInvitation revoked = invitationWithStatus(InvitationStatus.REVOKED);
        when(invitationRepository.findById(invitationId)).thenReturn(Optional.of(revoked));

        service.revokeInvitation(invitationId, actingAdmin.getId());

        assertThat(revoked.getStatus()).isEqualTo(InvitationStatus.REVOKED);
        verify(invitationRepository, never()).save(any());
        verify(auditLogPort, never()).logSecurityEvent(any(), any(), any(), any());
    }

    @Test
    @DisplayName("ACCEPTED → 409 DomainStateConflictException (direct to user-revoke)")
    void acceptedInvitationConflicts() {
        GuestInvitation accepted = invitationWithStatus(InvitationStatus.ACCEPTED);
        when(invitationRepository.findById(invitationId)).thenReturn(Optional.of(accepted));

        assertThatThrownBy(() -> service.revokeInvitation(invitationId, actingAdmin.getId()))
                .isInstanceOf(DomainStateConflictException.class)
                .hasMessageContaining("accepted");

        verify(invitationRepository, never()).save(any());
        verify(auditLogPort, never()).logSecurityEvent(any(), any(), any(), any());
    }

    @Test
    @DisplayName("Not found → 404 ResourceNotFoundException")
    void notFound() {
        when(invitationRepository.findById(invitationId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.revokeInvitation(invitationId, actingAdmin.getId()))
                .isInstanceOf(ResourceNotFoundException.class);

        verify(invitationRepository, never()).save(any());
    }

    @Test
    @DisplayName("System context (null actor) → audited with null userId, never the invitation id")
    void nullActorAuditsNullUserId() {
        GuestInvitation pending = invitationWithStatus(InvitationStatus.PENDING);
        when(invitationRepository.findById(invitationId)).thenReturn(Optional.of(pending));

        service.revokeInvitation(invitationId, (UUID) null);

        verify(auditLogPort, times(1)).logSecurityEvent(
                isNull(),
                eq("GUEST_INVITATION_REVOKED"),
                isNull(),
                any(String.class));
    }
}
