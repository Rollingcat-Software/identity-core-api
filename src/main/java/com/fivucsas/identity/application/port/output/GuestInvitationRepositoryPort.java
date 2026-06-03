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

    Optional<GuestInvitation> findById(UUID id);

    Optional<GuestInvitation> findByInvitationToken(String token);

    Optional<GuestInvitation> findActiveInvitationByTenantAndEmail(UUID tenantId, String email);

    List<GuestInvitation> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);

    List<GuestInvitation> findByTenantIdAndStatus(UUID tenantId, InvitationStatus status);

    /**
     * #10 — Invitations RECEIVED by an email (member-side "My Invitations"),
     * across all tenants, most-recent first. Case-insensitive match.
     */
    List<GuestInvitation> findByEmailIgnoreCaseOrderByCreatedAtDesc(String email);

    /**
     * Cross-tenant listing for ROOT. Returns every invitation in the
     * platform, ordered most-recent first.
     */
    List<GuestInvitation> findAllOrderByCreatedAtDesc();

    /**
     * Cross-tenant status filter for ROOT.
     */
    List<GuestInvitation> findAllByStatusOrderByCreatedAtDesc(InvitationStatus status);

    long countActiveGuestsInTenant(UUID tenantId, Instant now);

    /**
     * Count of active guests across every tenant (ROOT dashboard).
     */
    long countActiveGuestsPlatformWide(Instant now);

    int expirePendingInvitations(Instant now);

    int expireAccessEndedInvitations(Instant now);
}
