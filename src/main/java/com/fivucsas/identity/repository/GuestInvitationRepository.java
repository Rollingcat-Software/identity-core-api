package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.InvitationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for GuestInvitation entity.
 * Manages guest invitation lifecycle and queries.
 */
@Repository
public interface GuestInvitationRepository extends JpaRepository<GuestInvitation, UUID> {

    /**
     * Find invitation by token.
     */
    Optional<GuestInvitation> findByInvitationToken(String token);

    /**
     * Find all invitations for a tenant.
     */
    List<GuestInvitation> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);

    /**
     * Find invitations by tenant and status.
     */
    List<GuestInvitation> findByTenantIdAndStatus(UUID tenantId, InvitationStatus status);

    /**
     * Cross-tenant variants used by SUPER_ADMIN listing — bypasses tenant
     * scoping so the platform owner can audit invitations across all tenants.
     */
    List<GuestInvitation> findAllByOrderByCreatedAtDesc();

    List<GuestInvitation> findAllByStatusOrderByCreatedAtDesc(InvitationStatus status);

    /**
     * Count active guests platform-wide (SUPER_ADMIN dashboard).
     */
    @Query("SELECT COUNT(gi) FROM GuestInvitation gi " +
           "WHERE gi.status = 'ACCEPTED' " +
           "AND gi.accessEndsAt > :now")
    long countActiveGuestsPlatformWide(@Param("now") Instant now);

    /**
     * Find active invitation for an email within a tenant.
     */
    @Query("SELECT gi FROM GuestInvitation gi " +
           "WHERE gi.tenant.id = :tenantId " +
           "AND gi.email = :email " +
           "AND gi.status IN ('PENDING', 'ACCEPTED')")
    Optional<GuestInvitation> findActiveInvitationByTenantAndEmail(
            @Param("tenantId") UUID tenantId,
            @Param("email") String email);

    /**
     * Find invitations that have expired (pending past expiry or accepted past access window).
     */
    @Query("SELECT gi FROM GuestInvitation gi " +
           "WHERE (gi.status = 'PENDING' AND gi.expiresAt < :now) " +
           "OR (gi.status = 'ACCEPTED' AND gi.accessEndsAt < :now)")
    List<GuestInvitation> findExpiredInvitations(@Param("now") Instant now);

    /**
     * Find all invitations created by a specific user.
     */
    List<GuestInvitation> findByInvitedByIdOrderByCreatedAtDesc(UUID invitedById);

    /**
     * Count active guests in a tenant.
     */
    @Query("SELECT COUNT(gi) FROM GuestInvitation gi " +
           "WHERE gi.tenant.id = :tenantId " +
           "AND gi.status = 'ACCEPTED' " +
           "AND gi.accessEndsAt > :now")
    long countActiveGuestsInTenant(@Param("tenantId") UUID tenantId, @Param("now") Instant now);

    /**
     * Expire pending invitations past their expiry time.
     */
    @Modifying
    @Query("UPDATE GuestInvitation gi SET gi.status = 'EXPIRED' " +
           "WHERE gi.status = 'PENDING' AND gi.expiresAt < :now")
    int expirePendingInvitations(@Param("now") Instant now);

    /**
     * Expire accepted invitations past their access window.
     */
    @Modifying
    @Query("UPDATE GuestInvitation gi SET gi.status = 'EXPIRED' " +
           "WHERE gi.status = 'ACCEPTED' AND gi.accessEndsAt < :now")
    int expireAccessEndedInvitations(@Param("now") Instant now);

    /**
     * Check if an active invitation exists for the given email in a tenant.
     */
    @Query("SELECT COUNT(gi) > 0 FROM GuestInvitation gi " +
           "WHERE gi.tenant.id = :tenantId " +
           "AND gi.email = :email " +
           "AND gi.status IN ('PENDING', 'ACCEPTED')")
    boolean existsActiveInvitation(@Param("tenantId") UUID tenantId, @Param("email") String email);
}
