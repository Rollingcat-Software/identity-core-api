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
        GuestInvitationResponseBuilder builder = GuestInvitationResponse.builder()
                .id(invitation.getId())
                .tenantId(invitation.getTenant().getId())
                .email(invitation.getEmail())
                .status(invitation.getStatus().name())
                .invitedByEmail(invitation.getInvitedBy().getEmail())
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
            builder.guestUserId(invitation.getUser().getId())
                   .guestFirstName(invitation.getUser().getFirstName())
                   .guestLastName(invitation.getUser().getLastName());
        }

        return builder.build();
    }
}
