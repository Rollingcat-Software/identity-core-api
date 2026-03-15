package com.fivucsas.identity.application.service;

import com.fivucsas.identity.entity.*;
import com.fivucsas.identity.application.port.output.GuestInvitationRepositoryPort;
import com.fivucsas.identity.domain.repository.UserRepository;
import com.fivucsas.identity.application.port.output.UserRoleRepositoryPort;
import com.fivucsas.identity.application.port.output.RoleRepositoryPort;
import com.fivucsas.identity.domain.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Manages the complete guest user lifecycle: invitation, creation, and auto-expiration.
 *
 * <p>Key responsibilities:
 * <ul>
 *   <li>Creating guest invitations with configurable access windows</li>
 *   <li>Processing invitation acceptance (guest user creation)</li>
 *   <li>Revoking guest access</li>
 *   <li>Extending guest access duration</li>
 *   <li>Scheduled cleanup of expired guests (runs every 15 minutes)</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GuestLifecycleService {

    private final GuestInvitationRepositoryPort invitationRepository;
    private final UserRepository userRepository;
    private final UserRoleRepositoryPort userRoleRepository;
    private final RoleRepositoryPort roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String GUEST_ROLE_ID = "20000000-0000-0000-0000-000000000008";

    /**
     * Creates a guest invitation.
     *
     * @param tenant the tenant to invite the guest into
     * @param email the guest's email
     * @param invitedBy the user creating the invitation
     * @param accessDurationHours how many hours the guest will have access
     * @param message optional message to include in the invitation
     * @return the created invitation
     */
    @Transactional
    public GuestInvitation createInvitation(Tenant tenant, String email, User invitedBy,
                                            int accessDurationHours, String message) {
        // Check for existing active invitation
        if (invitationRepository.existsActiveInvitation(tenant.getId(), email)) {
            throw new IllegalStateException("An active invitation already exists for " + email + " in this tenant");
        }

        Instant now = Instant.now();
        Instant accessEnds = now.plus(accessDurationHours, ChronoUnit.HOURS);
        // Invitation token expires in 48 hours (or when access window ends, whichever is sooner)
        Instant invitationExpires = now.plus(48, ChronoUnit.HOURS);
        if (accessEnds.isBefore(invitationExpires)) {
            invitationExpires = accessEnds;
        }

        String token = generateInvitationToken();

        GuestInvitation invitation = GuestInvitation.builder()
                .tenant(tenant)
                .email(email)
                .invitedBy(invitedBy)
                .invitationToken(token)
                .message(message)
                .expiresAt(invitationExpires)
                .accessStartsAt(now)
                .accessEndsAt(accessEnds)
                .maxExtensions(3)
                .build();

        GuestInvitation saved = invitationRepository.save(invitation);
        log.info("Guest invitation created for {} in tenant {} by {}, access until {}",
                email, tenant.getName(), invitedBy.getEmail(), accessEnds);
        return saved;
    }

    /**
     * Accepts a guest invitation using the invitation token.
     * Creates the guest user account with appropriate roles.
     *
     * @param token the invitation token
     * @param firstName guest's first name
     * @param lastName guest's last name
     * @param password guest's chosen password
     * @return the created guest user
     */
    @Transactional
    public User acceptInvitation(String token, String firstName, String lastName, String password) {
        GuestInvitation invitation = invitationRepository.findByInvitationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid invitation token"));

        if (invitation.getStatus() != InvitationStatus.PENDING) {
            throw new IllegalStateException("Invitation is no longer pending (status: " + invitation.getStatus() + ")");
        }

        if (invitation.isInvitationExpired()) {
            invitation.expire();
            invitationRepository.save(invitation);
            throw new IllegalStateException("Invitation has expired");
        }

        // Create guest user
        User guestUser = User.builder()
                .tenant(invitation.getTenant())
                .email(invitation.getEmail())
                .passwordHash(passwordEncoder.encode(password))
                .firstName(firstName)
                .lastName(lastName)
                .status(UserStatus.ACTIVE)
                .userType(UserType.GUEST)
                .expiresAt(invitation.getAccessEndsAt())
                .invitedBy(invitation.getInvitedBy())
                .build();

        User savedUser = userRepository.save(guestUser);

        // Assign default GUEST_ACCESS role
        roleRepository.findById(UUID.fromString(GUEST_ROLE_ID)).ifPresent(guestRole -> {
            UserRole userRole = UserRole.create(savedUser, guestRole, invitation.getInvitedBy().getId(),
                    invitation.getAccessEndsAt());
            userRoleRepository.save(userRole);
        });

        // Accept the invitation
        invitation.accept(savedUser);
        invitationRepository.save(invitation);

        log.info("Guest invitation accepted: user {} created in tenant {}, expires at {}",
                savedUser.getEmail(), invitation.getTenant().getName(), invitation.getAccessEndsAt());

        return savedUser;
    }

    /**
     * Revokes a guest's access immediately.
     * Soft-deletes the user, revokes tokens, and removes roles.
     */
    @Transactional
    public void revokeGuestAccess(UUID guestUserId, User revokedBy) {
        User guestUser = userRepository.findById(guestUserId)
                .orElseThrow(() -> new IllegalArgumentException("Guest user not found"));

        if (guestUser.getUserType() != UserType.GUEST) {
            throw new IllegalStateException("User is not a guest");
        }

        // Revoke the invitation
        invitationRepository.findActiveInvitationByTenantAndEmail(
                guestUser.getTenant().getId(), guestUser.getEmail()
        ).ifPresent(inv -> {
            inv.revoke(revokedBy);
            invitationRepository.save(inv);
        });

        // Remove roles
        userRoleRepository.deleteAllByUserId(guestUserId);

        // Deactivate user
        guestUser.deactivate();
        userRepository.save(guestUser);

        log.info("Guest access revoked for user {} by {}", guestUser.getEmail(), revokedBy.getEmail());
    }

    /**
     * Extends a guest's access duration.
     */
    @Transactional
    public void extendGuestAccess(UUID guestUserId, int additionalHours, User extendedBy) {
        User guestUser = userRepository.findById(guestUserId)
                .orElseThrow(() -> new IllegalArgumentException("Guest user not found"));

        if (guestUser.getUserType() != UserType.GUEST) {
            throw new IllegalStateException("User is not a guest");
        }

        Instant newExpiry = (guestUser.getExpiresAt() != null ? guestUser.getExpiresAt() : Instant.now())
                .plus(additionalHours, ChronoUnit.HOURS);

        guestUser.setExpiresAt(newExpiry);
        userRepository.save(guestUser);

        // Update invitation if exists
        invitationRepository.findActiveInvitationByTenantAndEmail(
                guestUser.getTenant().getId(), guestUser.getEmail()
        ).ifPresent(inv -> {
            inv.extendAccess(newExpiry);
            invitationRepository.save(inv);
        });

        // Update user_role expiration
        List<UserRole> roles = userRoleRepository.findByIdUserId(guestUserId);
        for (UserRole ur : roles) {
            ur.setExpiresAt(newExpiry);
        }
        userRoleRepository.saveAll(roles);

        log.info("Guest access extended for user {} until {} by {}",
                guestUser.getEmail(), newExpiry, extendedBy.getEmail());
    }

    /**
     * Scheduled task to clean up expired guests.
     * Runs every 15 minutes.
     * Soft-deletes expired guest users and cleans up their tokens and roles.
     */
    @Scheduled(fixedRate = 900000) // 15 minutes
    @Transactional
    public void cleanupExpiredGuests() {
        log.debug("Running expired guest cleanup...");
        Instant now = Instant.now();

        // Find expired guest users
        List<User> expiredGuests = userRepository.findExpiredGuests(now);

        if (expiredGuests.isEmpty()) {
            log.debug("No expired guests found");
            return;
        }

        int count = 0;
        for (User guest : expiredGuests) {
            try {
                // Remove roles
                userRoleRepository.deleteAllByUserId(guest.getId());

                // Deactivate user (soft delete)
                guest.deactivate();
                userRepository.save(guest);

                count++;
                log.info("Expired guest user cleaned up: {} (expired at {})",
                        guest.getEmail(), guest.getExpiresAt());
            } catch (Exception e) {
                log.error("Failed to clean up expired guest {}: {}", guest.getEmail(), e.getMessage());
            }
        }

        // Expire stale invitations
        int expiredPending = invitationRepository.expirePendingInvitations(now);
        int expiredAccepted = invitationRepository.expireAccessEndedInvitations(now);

        // Clean up expired role assignments (not just guests)
        int expiredRoles = userRoleRepository.deleteExpiredAssignments(now);

        log.info("Guest cleanup completed: {} users deactivated, {} pending invitations expired, " +
                 "{} accepted invitations expired, {} expired role assignments removed",
                count, expiredPending, expiredAccepted, expiredRoles);
    }

    private String generateInvitationToken() {
        byte[] tokenBytes = new byte[48];
        SECURE_RANDOM.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
