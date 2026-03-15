package com.fivucsas.identity.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Tracks guest user invitations with time-bounded access windows.
 *
 * <p>Lifecycle:
 * <ol>
 *   <li>PENDING: Tenant admin creates invitation with access window</li>
 *   <li>ACCEPTED: Guest registers using invitation token</li>
 *   <li>EXPIRED: Access window ends, scheduled job cleans up the guest user</li>
 *   <li>REVOKED: Tenant admin manually revokes access before expiry</li>
 * </ol>
 */
@Entity
@Table(name = "guest_invitations")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class GuestInvitation {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 255)
    private String email;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "invited_by", nullable = false)
    private User invitedBy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @Setter
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private InvitationStatus status = InvitationStatus.PENDING;

    @Column(name = "invitation_token", unique = true, length = 512)
    private String invitationToken;

    @Column(columnDefinition = "TEXT")
    private String message;

    // Time constraints
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "access_starts_at", nullable = false)
    @Builder.Default
    private Instant accessStartsAt = Instant.now();

    @Column(name = "access_ends_at", nullable = false)
    private Instant accessEndsAt;

    // Extension tracking
    @Column(name = "max_extensions")
    @Builder.Default
    private int maxExtensions = 0;

    @Column(name = "extension_count")
    @Builder.Default
    private int extensionCount = 0;

    @Column(columnDefinition = "jsonb")
    private String metadata;

    // Lifecycle timestamps
    @Column(name = "accepted_at")
    private Instant acceptedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "revoked_by")
    private User revokedBy;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;

    // ========== Business Methods ==========

    /**
     * Accepts the invitation and links to the newly created guest user.
     */
    public void accept(User guestUser) {
        if (this.status != InvitationStatus.PENDING) {
            throw new IllegalStateException("Cannot accept invitation in status: " + this.status);
        }
        if (isInvitationExpired()) {
            throw new IllegalStateException("Invitation has expired");
        }
        this.status = InvitationStatus.ACCEPTED;
        this.user = guestUser;
        this.acceptedAt = Instant.now();
    }

    /**
     * Revokes the invitation (by tenant admin).
     */
    public void revoke(User revokedByUser) {
        if (this.status == InvitationStatus.REVOKED) {
            throw new IllegalStateException("Invitation is already revoked");
        }
        this.status = InvitationStatus.REVOKED;
        this.revokedAt = Instant.now();
        this.revokedBy = revokedByUser;
    }

    /**
     * Marks the invitation as expired.
     */
    public void expire() {
        this.status = InvitationStatus.EXPIRED;
    }

    /**
     * Extends the guest access window.
     */
    public void extendAccess(Instant newAccessEndsAt) {
        if (this.extensionCount >= this.maxExtensions && this.maxExtensions > 0) {
            throw new IllegalStateException("Maximum extensions reached");
        }
        if (newAccessEndsAt.isBefore(this.accessEndsAt)) {
            throw new IllegalArgumentException("New end date must be after current end date");
        }
        this.accessEndsAt = newAccessEndsAt;
        this.extensionCount++;

        // Also update the linked user's expiration
        if (this.user != null) {
            this.user.setExpiresAt(newAccessEndsAt);
        }
    }

    /**
     * Checks if the invitation token has expired (before acceptance).
     */
    public boolean isInvitationExpired() {
        return this.expiresAt.isBefore(Instant.now());
    }

    /**
     * Checks if the guest access window has ended.
     */
    public boolean isAccessExpired() {
        return this.accessEndsAt.isBefore(Instant.now());
    }

    /**
     * Checks if the invitation is currently active (accepted and within access window).
     */
    public boolean isActive() {
        return this.status == InvitationStatus.ACCEPTED
            && !isAccessExpired()
            && Instant.now().isAfter(this.accessStartsAt);
    }

    /**
     * Checks if this invitation can still be extended.
     */
    public boolean canExtend() {
        return this.maxExtensions == 0 || this.extensionCount < this.maxExtensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GuestInvitation)) return false;
        GuestInvitation that = (GuestInvitation) o;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
