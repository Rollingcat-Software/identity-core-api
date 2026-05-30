package com.fivucsas.identity.dto;

import com.fivucsas.identity.entity.GuestInvitation;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * Response DTO for guest invitation data.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GuestInvitationResponse {

    private UUID id;
    private UUID tenantId;
    private String email;
    private String status;
    private String invitedByEmail;
    private String message;
    private Instant accessStartsAt;
    private Instant accessEndsAt;
    private Instant expiresAt;
    private int extensionCount;
    private int maxExtensions;
    private boolean canExtend;
    private Instant acceptedAt;
    private Instant createdAt;

    // Guest user details (if accepted)
    private UUID guestUserId;
    private String guestFirstName;
    private String guestLastName;

    public static GuestInvitationResponse from(GuestInvitation invitation) {
        // P1-4 lazy-proxy guard: the inviter / guest User can be soft-deleted
        // (@SQLRestriction("deleted_at IS NULL") hides it), so initializing the proxy
        // to read a name/email throws EntityNotFoundException and 500s the whole
        // /guests list. .getId() is an FK read (no init); name/email init the proxy
        // and are guarded here, falling back to null when the user row is gone.
        String invitedByEmail = null;
        try {
            if (invitation.getInvitedBy() != null) {
                org.hibernate.Hibernate.initialize(invitation.getInvitedBy());
                invitedByEmail = invitation.getInvitedBy().getEmail();
            }
        } catch (jakarta.persistence.EntityNotFoundException ignored) {
            // inviter soft-deleted — leave null
        }

        GuestInvitationResponseBuilder builder = GuestInvitationResponse.builder()
                .id(invitation.getId())
                .tenantId(invitation.getTenant().getId())
                .email(invitation.getEmail())
                .status(invitation.getStatus().name())
                .invitedByEmail(invitedByEmail)
                .message(invitation.getMessage())
                .accessStartsAt(invitation.getAccessStartsAt())
                .accessEndsAt(invitation.getAccessEndsAt())
                .expiresAt(invitation.getExpiresAt())
                .extensionCount(invitation.getExtensionCount())
                .maxExtensions(invitation.getMaxExtensions())
                .canExtend(invitation.canExtend())
                .acceptedAt(invitation.getAcceptedAt())
                .createdAt(invitation.getCreatedAt());

        if (invitation.getUser() != null) {
            builder.guestUserId(invitation.getUser().getId());
            try {
                org.hibernate.Hibernate.initialize(invitation.getUser());
                builder.guestFirstName(invitation.getUser().getFirstName())
                       .guestLastName(invitation.getUser().getLastName());
            } catch (jakarta.persistence.EntityNotFoundException ignored) {
                // guest user soft-deleted — leave name fields null
            }
        }

        return builder.build();
    }
}
