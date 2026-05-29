package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.port.input.SwitchMembershipUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.MembershipSwitchPort;
import com.fivucsas.identity.application.port.output.MembershipSwitchPort.SwitchTargetView;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.domain.exception.MembershipNotSwitchableException;
import com.fivucsas.identity.domain.exception.MembershipSwitchForbiddenException;
import com.fivucsas.identity.domain.exception.ResourceNotFoundException;
import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Phase-5 in-session membership switch (see
 * {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md} § "Phase 5").
 *
 * <p>An authenticated person assumes another of THEIR OWN linked memberships
 * without re-login. This is a TOKEN EXCHANGE / account switch, NOT a privilege
 * grant: the caller may only assume memberships under the SAME platform identity
 * (ownership proven at link time).</p>
 *
 * <p><b>Security posture — the same-identity HARD GATE is the ONLY barrier
 * between accounts.</b> The flow trusts NOTHING from the request beyond
 * {@code targetUserId}: the caller's identity is derived from the authenticated
 * principal, the target's identity from its persisted row, and a switch is
 * refused (403) unless the two match. Tenant / roles / permissions are carried
 * over from the target membership's own row at token-mint time — never from the
 * request.</p>
 *
 * <p><b>Hexagonal boundary.</b> All {@code users}-row access + the token mint go
 * through {@link MembershipSwitchPort} (DTOs only) so this service never imports
 * {@code entity.User} — the {@code UserDomainBoundaryTest} ratchet. Caller
 * identity resolution uses {@link UserRepository#findIdentityIdById} (a projection
 * query, no entity exposure).</p>
 */
@Service
@Slf4j
public class SwitchMembershipService implements SwitchMembershipUseCase {

    private final MembershipSwitchPort switchPort;
    private final UserRepository userRepository;
    private final AuditLogPort auditLogPort;

    /**
     * When true, a switch requires a fresh credential (the caller's current
     * password) in the request — limits blast radius if one session is stolen
     * (a switch can reach a higher-privileged linked membership). Default
     * {@code false}: ownership is already proven, so v1 ships frictionless;
     * operators can tighten via {@code app.identity.require-stepup-on-switch}.
     */
    private final boolean requireStepUpOnSwitch;

    public SwitchMembershipService(
            MembershipSwitchPort switchPort,
            UserRepository userRepository,
            AuditLogPort auditLogPort,
            @Value("${app.identity.require-stepup-on-switch:false}") boolean requireStepUpOnSwitch) {
        this.switchPort = switchPort;
        this.userRepository = userRepository;
        this.auditLogPort = auditLogPort;
        this.requireStepUpOnSwitch = requireStepUpOnSwitch;
    }

    @Override
    @Transactional
    public AuthResponse switchMembership(UUID callerUserId,
                                         UUID targetUserId,
                                         String stepUpPassword,
                                         List<String> amr,
                                         Long authTime,
                                         String ipAddress,
                                         String userAgent) {
        if (callerUserId == null) {
            throw new InvalidCredentialsException("Authentication required");
        }
        if (targetUserId == null) {
            throw new IllegalArgumentException("targetUserId is required");
        }

        // 1. Resolve the caller's platform identity.
        UUID callerIdentityId = userRepository.findIdentityIdById(callerUserId)
                .orElseThrow(() -> new MembershipSwitchForbiddenException(
                        "Your account has no platform identity yet"));

        // 2. Load the target membership (filter bypassed inside the adapter).
        SwitchTargetView target = switchPort.findSwitchTarget(targetUserId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Membership", String.valueOf(targetUserId)));

        // No-op switch to self: return a fresh session for the SAME membership
        // (cheap + idempotent — the caller already owns it; treat like a switch
        // to your current account rather than a 400 round-trip).
        if (targetUserId.equals(callerUserId)) {
            log.debug("Membership-switch to self (no-op) caller={}", callerUserId);
            return mintAndAudit(callerIdentityId, target, callerUserId, stepUpPassword,
                    amr, authTime, ipAddress, userAgent);
        }

        // 3. HARD GATE — the ONLY barrier between accounts. Target must belong to
        // the caller's OWN identity. Null target identity is also a hard fail.
        if (target.identityId() == null || !target.identityId().equals(callerIdentityId)) {
            log.warn("AUDIT: membership-switch DENIED (cross-identity) caller={} callerIdentity={} "
                            + "target={} targetIdentity={}",
                    callerUserId, callerIdentityId, targetUserId, target.identityId());
            auditLogPort.logSecurityEvent(
                    callerUserId.toString(),
                    "MEMBERSHIP_SWITCH_DENIED",
                    ipAddress,
                    "Cross-identity switch attempt to membership " + targetUserId);
            throw new MembershipSwitchForbiddenException();
        }

        return mintAndAudit(callerIdentityId, target, callerUserId, stepUpPassword,
                amr, authTime, ipAddress, userAgent);
    }

    /**
     * Shared tail: switchability check, optional step-up, token mint, audit.
     * Reached ONLY after the same-identity HARD GATE (or the self no-op) passed.
     */
    private AuthResponse mintAndAudit(UUID callerIdentityId,
                                      SwitchTargetView target,
                                      UUID callerUserId,
                                      String stepUpPassword,
                                      List<String> amr,
                                      Long authTime,
                                      String ipAddress,
                                      String userAgent) {
        // 4. Target must be currently switchable: ACTIVE (not locked/suspended/
        // soft-deleted) AND its tenant ACTIVE — else 409.
        if (!target.userActive()) {
            throw new MembershipNotSwitchableException(
                    "The target membership is not active");
        }
        if (!target.tenantActive()) {
            throw new MembershipNotSwitchableException(
                    "The target membership's tenant is not active");
        }

        // 4b. Optional step-up (config-gated). When enabled, require a fresh
        // password on the CALLER before issuing — fail closed, no token minted.
        if (requireStepUpOnSwitch) {
            if (stepUpPassword == null || stepUpPassword.isEmpty()
                    || !switchPort.verifyPassword(callerUserId, stepUpPassword)) {
                auditLogPort.logSecurityEvent(
                        callerUserId.toString(),
                        "MEMBERSHIP_SWITCH_STEPUP_FAILED",
                        ipAddress,
                        "Step-up re-authentication failed during membership switch");
                throw new InvalidCredentialsException("Step-up re-authentication failed");
            }
        }

        // 5. Mint the new token pair AS the target membership (REUSES the
        // post-login token-mint path inside the adapter).
        AuthResponse response = switchPort.mintSwitchedTokens(
                target.userId(), amr, authTime, callerUserId, ipAddress, userAgent);

        // 6. Audit MEMBERSHIP_SWITCHED — actor = caller, resource = target
        // user/tenant. Use logTenantManagementEvent so the caller is the audit
        // actor (user_id) and the TARGET TENANT is the resource — a tenant id is
        // NEVER written into the user_id slot.
        auditLogPort.logTenantManagementEvent(
                callerUserId.toString(),
                "MEMBERSHIP_SWITCHED",
                target.tenantId() != null ? target.tenantId().toString() : null,
                "Membership switch: caller " + callerUserId + " (identity " + callerIdentityId
                        + ") assumed membership " + target.userId()
                        + " in tenant " + target.tenantId());
        log.info("AUDIT: MEMBERSHIP_SWITCHED caller={} target={} tenant={} identity={}",
                callerUserId, target.userId(), target.tenantId(), callerIdentityId);

        return response;
    }
}
