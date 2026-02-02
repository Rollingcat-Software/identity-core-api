package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.service.GuestLifecycleService;
import com.fivucsas.identity.dto.AcceptInvitationRequest;
import com.fivucsas.identity.dto.ExtendGuestAccessRequest;
import com.fivucsas.identity.dto.GuestInvitationResponse;
import com.fivucsas.identity.dto.InviteGuestRequest;
import com.fivucsas.identity.entity.GuestInvitation;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.repository.GuestInvitationRepository;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * REST controller for guest user lifecycle management.
 *
 * <p>Provides endpoints for:
 * <ul>
 *   <li>Inviting guests (requires guest:invite permission)</li>
 *   <li>Accepting invitations (public endpoint, token-based)</li>
 *   <li>Listing guest invitations (requires guest:read permission)</li>
 *   <li>Revoking guest access (requires guest:revoke permission)</li>
 *   <li>Extending guest access (requires guest:extend permission)</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/guests")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Guest Management", description = "Guest invitation and lifecycle operations")
public class GuestController {

    private final GuestLifecycleService guestLifecycleService;
    private final GuestInvitationRepository invitationRepository;
    private final RbacAuthorizationService rbacService;

    @PostMapping("/invite")
    @Operation(summary = "Invite a guest user",
               description = "Creates a guest invitation with a time-bounded access window. Requires guest:invite permission.")
    @PreAuthorize("@rbac.hasPermission('guest:invite')")
    public ResponseEntity<GuestInvitationResponse> inviteGuest(
            @Valid @RequestBody InviteGuestRequest request) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        log.info("POST /api/v1/guests/invite - Inviting guest {} by {}",
                request.getEmail(), currentUser.getEmail());

        GuestInvitation invitation = guestLifecycleService.createInvitation(
                currentUser.getTenant(),
                request.getEmail(),
                currentUser,
                request.getAccessDurationHours(),
                request.getMessage()
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(GuestInvitationResponse.from(invitation));
    }

    @PostMapping("/accept")
    @Operation(summary = "Accept a guest invitation",
               description = "Public endpoint. Accepts an invitation using the token and creates the guest user account.")
    public ResponseEntity<Void> acceptInvitation(
            @Valid @RequestBody AcceptInvitationRequest request) {

        log.info("POST /api/v1/guests/accept - Accepting invitation");

        guestLifecycleService.acceptInvitation(
                request.getToken(),
                request.getFirstName(),
                request.getLastName(),
                request.getPassword()
        );

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping
    @Operation(summary = "List guest invitations for current tenant",
               description = "Returns all guest invitations for the authenticated user's tenant.")
    @PreAuthorize("@rbac.hasPermission('guest:read')")
    public ResponseEntity<List<GuestInvitationResponse>> listInvitations(
            @RequestParam(required = false) String status) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        UUID tenantId = currentUser.getTenant().getId();

        List<GuestInvitation> invitations;
        if (status != null && !status.isEmpty()) {
            invitations = invitationRepository.findByTenantIdAndStatus(
                    tenantId,
                    com.fivucsas.identity.entity.InvitationStatus.valueOf(status.toUpperCase())
            );
        } else {
            invitations = invitationRepository.findByTenantIdOrderByCreatedAtDesc(tenantId);
        }

        List<GuestInvitationResponse> responses = invitations.stream()
                .map(GuestInvitationResponse::from)
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }

    @GetMapping("/count")
    @Operation(summary = "Count active guests in tenant")
    @PreAuthorize("@rbac.hasPermission('guest:read')")
    public ResponseEntity<Long> countActiveGuests() {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        long count = invitationRepository.countActiveGuestsInTenant(
                currentUser.getTenant().getId(), Instant.now());

        return ResponseEntity.ok(count);
    }

    @PostMapping("/{guestUserId}/revoke")
    @Operation(summary = "Revoke guest access",
               description = "Immediately revokes a guest user's access. The guest account is deactivated.")
    @PreAuthorize("@rbac.hasPermission('guest:revoke')")
    public ResponseEntity<Void> revokeGuestAccess(@PathVariable UUID guestUserId) {
        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        log.info("POST /api/v1/guests/{}/revoke - Revoking access by {}",
                guestUserId, currentUser.getEmail());

        guestLifecycleService.revokeGuestAccess(guestUserId, currentUser);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{guestUserId}/extend")
    @Operation(summary = "Extend guest access duration",
               description = "Extends a guest user's access by the specified number of hours.")
    @PreAuthorize("@rbac.hasPermission('guest:extend')")
    public ResponseEntity<Void> extendGuestAccess(
            @PathVariable UUID guestUserId,
            @Valid @RequestBody ExtendGuestAccessRequest request) {

        User currentUser = rbacService.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        log.info("POST /api/v1/guests/{}/extend - Extending access by {} hours by {}",
                guestUserId, request.getAdditionalHours(), currentUser.getEmail());

        guestLifecycleService.extendGuestAccess(guestUserId, request.getAdditionalHours(), currentUser);

        return ResponseEntity.ok().build();
    }
}
