package com.fivucsas.identity.application.port.output;

import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.InvitationStatus;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Output port for GuestInvitation persistence operations.
 */
public interface GuestInvitationRepositoryPort {

    boolean existsActiveInvitation(UUID tenantId, String email);

    GuestInvitation save(GuestInvitation invitation);

    Optional<GuestInvitation> findByInvitationToken(String token);

    Optional<GuestInvitation> findActiveInvitationByTenantAndEmail(UUID tenantId, String email);

    List<GuestInvitation> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);

    List<GuestInvitation> findByTenantIdAndStatus(UUID tenantId, InvitationStatus status);

    long countActiveGuestsInTenant(UUID tenantId, Instant now);

    int expirePendingInvitations(Instant now);

    int expireAccessEndedInvitations(Instant now);
}
