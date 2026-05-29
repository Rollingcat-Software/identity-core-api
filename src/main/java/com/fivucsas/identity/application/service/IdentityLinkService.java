package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.IdentityMeResponse;
import com.fivucsas.identity.application.port.input.IdentityLinkUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.IdentityLinkUserPort;
import com.fivucsas.identity.application.port.output.IdentityLinkUserPort.MembershipView;
import com.fivucsas.identity.domain.exception.IdentityLinkException;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.entity.Identity;
import com.fivucsas.identity.entity.IdentityEmail;
import com.fivucsas.identity.infrastructure.email.EmailService;
import com.fivucsas.identity.infrastructure.otp.OtpService;
import com.fivucsas.identity.repository.IdentityEmailRepository;
import com.fivucsas.identity.repository.IdentityRepository;
import com.fivucsas.identity.security.RateLimitService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Phase-2 account linking (see {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md}).
 *
 * <p>Lets one person fold another tenant account (a different email) into their
 * platform-level {@link Identity} after proving (a) control of the target email
 * (an OTP sent to it) AND (b) caller step-up (a fresh password re-entry). The
 * caller's identity is ALWAYS derived from the authenticated caller — never a
 * request parameter — so a caller can only ever operate on their own identity.</p>
 *
 * <p><b>No new migration.</b> The link-OTP challenge reuses the existing Redis
 * {@link OtpService} (same store/TTL/attempt-counter as the email-OTP auth
 * handlers), keyed per {@code (callerUserId, targetEmail)}. Audit goes through
 * the existing {@link AuditLogPort#logSecurityEvent}.</p>
 *
 * <p><b>Hexagonal boundary.</b> All {@code users}-row access goes through
 * {@link IdentityLinkUserPort} (DTOs only) so this service never imports
 * {@code entity.User} — the {@code UserDomainBoundaryTest} ratchet. It DOES
 * touch {@link Identity}/{@link IdentityEmail}, which are cross-tenant
 * platform-level entities (NOT fenced by that ratchet, NOT tenant-scoped).</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class IdentityLinkService implements IdentityLinkUseCase {

    private final IdentityLinkUserPort userPort;
    private final IdentityRepository identityRepository;
    private final IdentityEmailRepository identityEmailRepository;
    private final OtpService otpService;
    private final EmailService emailService;
    private final RateLimitService rateLimitService;
    private final AuditLogPort auditLogPort;

    @Override
    @Transactional
    public void initiateLink(UUID callerUserId, String targetEmail) {
        String normalizedEmail = normalizeEmail(targetEmail);
        MembershipView caller = requireCaller(callerUserId);
        UUID callerIdentityId = requireIdentity(caller);

        // Rate limit per (caller, target) — reuses the password-reset bucket
        // (OTP-to-email send, hourly cap), the closest-matching existing infra.
        String rlKey = "identity-link:" + callerUserId + ":" + normalizedEmail;
        if (!rateLimitService.allowPasswordResetAttempt(rlKey)) {
            // Surface as a generic rate-limit; the interceptor/handler maps 429.
            throw new IdentityLinkException(
                    "Too many link attempts for this email. Please try again later.");
        }

        MembershipView target = userPort.findMembershipByEmail(normalizedEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User", normalizedEmail));

        validateLinkable(caller, callerIdentityId, target);

        // Send the OTP to the TARGET email (proof of control of the other account).
        String otpKey = buildOtpKey(callerUserId, normalizedEmail);
        String code = otpService.generate(otpKey);
        emailService.sendOtp(normalizedEmail, code);

        auditLogPort.logSecurityEvent(
                callerUserId.toString(),
                "IDENTITY_LINK_INITIATED",
                null,
                "Account-link OTP sent to target membership " + target.userId());
        log.info("Account-link OTP sent for caller={} target={}", callerUserId, target.userId());
    }

    @Override
    @Transactional
    public void confirmLink(UUID callerUserId, String targetEmail, String otp, String stepUpPassword) {
        String normalizedEmail = normalizeEmail(targetEmail);
        MembershipView caller = requireCaller(callerUserId);
        UUID callerIdentityId = requireIdentity(caller);

        MembershipView target = userPort.findMembershipByEmail(normalizedEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User", normalizedEmail));

        // Idempotency: already part of the caller's identity → no-op success.
        if (callerIdentityId.equals(target.identityId())) {
            log.info("Account-link confirm is a no-op (already linked) caller={} target={}",
                    callerUserId, target.userId());
            return;
        }

        validateLinkable(caller, callerIdentityId, target);

        // (a) Proof of control of the target email — the OTP.
        String otpKey = buildOtpKey(callerUserId, normalizedEmail);
        OtpService.ValidationResult otpResult = otpService.validateWithResult(otpKey, otp == null ? "" : otp);
        if (!otpResult.isValid()) {
            auditLogPort.logSecurityEvent(callerUserId.toString(), "IDENTITY_LINK_OTP_FAILED",
                    null, "Invalid OTP for target " + normalizedEmail);
            throw new InvalidCredentialsException("Invalid or expired verification code");
        }

        // (b) Caller step-up — a fresh re-entry of the caller's current password.
        if (stepUpPassword == null || stepUpPassword.isEmpty()
                || !userPort.verifyPassword(callerUserId, stepUpPassword)) {
            // OTP was consumed by the valid check above; a failed step-up here
            // forces a fresh initiate, which is the intended fail-closed posture.
            auditLogPort.logSecurityEvent(callerUserId.toString(), "IDENTITY_LINK_STEPUP_FAILED",
                    null, "Step-up re-authentication failed during account link");
            throw new InvalidCredentialsException("Step-up re-authentication failed");
        }

        UUID orphanedIdentityId = target.identityId();

        // Re-point the target membership to the caller's identity.
        userPort.repointIdentity(target.userId(), callerIdentityId);

        // Move the target's email into the caller's identity (verified=true).
        moveEmailToIdentity(normalizedEmail, callerIdentityId);

        // Delete the now-orphaned identity if it has no remaining memberships.
        deleteIfOrphaned(orphanedIdentityId);

        auditLogPort.logSecurityEvent(
                callerUserId.toString(),
                "IDENTITY_LINKED",
                null,
                "Linked membership " + target.userId() + " (tenant " + target.tenantId()
                        + ") into identity " + callerIdentityId);
        log.info("IDENTITY_LINKED caller={} target={} identity={}",
                callerUserId, target.userId(), callerIdentityId);
    }

    @Override
    @Transactional
    public void unlink(UUID callerUserId, UUID membershipUserId) {
        MembershipView caller = requireCaller(callerUserId);
        UUID callerIdentityId = requireIdentity(caller);

        MembershipView target = userPort.findMembershipByUserId(membershipUserId)
                .orElseThrow(() -> new ResourceNotFoundException("Membership", String.valueOf(membershipUserId)));

        // Guard: caller may only unlink memberships within their OWN identity.
        if (!callerIdentityId.equals(target.identityId())) {
            throw new IdentityLinkException(
                    "You can only unlink memberships within your own identity");
        }

        // Create a fresh identity for the split-off membership + its email row,
        // then re-point — never leaving a membership with a NULL identity.
        Identity fresh = identityRepository.save(Identity.builder()
                .displayName(target.email())
                .status("ACTIVE")
                .build());

        userPort.repointIdentity(target.userId(), fresh.getId());
        moveEmailToIdentity(normalizeEmail(target.email()), fresh.getId());

        auditLogPort.logSecurityEvent(
                callerUserId.toString(),
                "IDENTITY_UNLINKED",
                null,
                "Unlinked membership " + target.userId() + " from identity " + callerIdentityId
                        + " into fresh identity " + fresh.getId());
        log.info("IDENTITY_UNLINKED caller={} membership={} newIdentity={}",
                callerUserId, target.userId(), fresh.getId());
    }

    @Override
    @Transactional(readOnly = true)
    public IdentityMeResponse getMyIdentity(UUID callerUserId) {
        MembershipView caller = requireCaller(callerUserId);
        UUID identityId = requireIdentity(caller);

        // Cross-tenant read BY DESIGN: every membership is the caller's own row.
        List<IdentityMeResponse.MembershipView> memberships =
                userPort.findMembershipsByIdentityId(identityId).stream()
                        .map(m -> new IdentityMeResponse.MembershipView(
                                m.userId(), m.tenantId(), m.tenantName(), m.role(), m.active()))
                        .toList();

        List<IdentityMeResponse.EmailView> emails =
                identityEmailRepository.findByIdentityId(identityId).stream()
                        .map(e -> new IdentityMeResponse.EmailView(e.getEmail(), e.isVerified()))
                        .toList();

        return new IdentityMeResponse(identityId, emails, memberships);
    }

    // ---- helpers -----------------------------------------------------------

    /** Validates that {@code target} is a legal link target for {@code caller}. */
    private void validateLinkable(MembershipView caller, UUID callerIdentityId, MembershipView target) {
        // Already in the caller's identity — not a fresh link.
        if (callerIdentityId.equals(target.identityId())) {
            throw new IdentityLinkException("That account is already linked to your identity");
        }
        // Target membership must be ACTIVE.
        if (!target.active()) {
            throw new IdentityLinkException("The target account is not active");
        }
        // Block linking a membership in a tenant the caller already belongs to —
        // it would duplicate a membership in that tenant.
        boolean sameTenantExists = userPort.findMembershipsByIdentityId(callerIdentityId).stream()
                .anyMatch(m -> m.tenantId() != null && m.tenantId().equals(target.tenantId()));
        if (sameTenantExists) {
            throw new IdentityLinkException(
                    "You already have a membership in that tenant — accounts in the same "
                            + "tenant cannot be linked");
        }
    }

    /** Moves (or creates) the email row so it belongs to {@code identityId}, verified. */
    private void moveEmailToIdentity(String email, UUID identityId) {
        Identity identity = identityRepository.findById(identityId)
                .orElseThrow(() -> new ResourceNotFoundException("Identity", String.valueOf(identityId)));

        Optional<IdentityEmail> existing = identityEmailRepository.findByEmailIgnoreCase(email);
        if (existing.isPresent()) {
            IdentityEmail row = existing.get();
            if (identityId.equals(row.getIdentityId())) {
                return; // already where it should be
            }
            // Re-home + verify. IdentityEmail has no setters, so replace the row.
            identityEmailRepository.delete(row);
            identityEmailRepository.flush();
        }
        identityEmailRepository.save(IdentityEmail.builder()
                .identity(identity)
                .email(email)
                .verified(true)
                .verifiedAt(Instant.now())
                .build());
    }

    /** Deletes {@code identityId} iff no memberships remain attached to it. */
    private void deleteIfOrphaned(UUID identityId) {
        if (identityId == null) {
            return;
        }
        boolean stillHasMembers = !userPort.findMembershipsByIdentityId(identityId).isEmpty();
        if (stillHasMembers) {
            return;
        }
        // Remove any leftover email rows on the orphan, then the identity itself.
        identityEmailRepository.findByIdentityId(identityId)
                .forEach(identityEmailRepository::delete);
        identityRepository.deleteById(identityId);
        log.info("Deleted orphaned identity {} (no remaining memberships)", identityId);
    }

    private MembershipView requireCaller(UUID callerUserId) {
        if (callerUserId == null) {
            throw new InvalidCredentialsException("Authentication required");
        }
        return userPort.findMembershipByUserId(callerUserId)
                .orElseThrow(() -> new ResourceNotFoundException("User", String.valueOf(callerUserId)));
    }

    private UUID requireIdentity(MembershipView caller) {
        if (caller.identityId() == null) {
            // Phase-1 backfill guarantees every user has an identity; defend anyway.
            throw new IdentityLinkException("Your account has no platform identity yet");
        }
        return caller.identityId();
    }

    private String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }
        return email.trim().toLowerCase();
    }

    private String buildOtpKey(UUID callerUserId, String normalizedEmail) {
        return "identity-link-otp:" + callerUserId + ":" + normalizedEmail;
    }
}
