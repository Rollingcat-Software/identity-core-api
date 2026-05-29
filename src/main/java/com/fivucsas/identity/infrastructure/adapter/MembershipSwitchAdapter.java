package com.fivucsas.identity.infrastructure.adapter;

import com.fivucsas.identity.application.dto.response.UserResponse;
import com.fivucsas.identity.application.mapper.UserResponseMapper;
import com.fivucsas.identity.application.port.output.MembershipSwitchPort;
import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.entity.RefreshToken;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.User;
import com.fivucsas.identity.infrastructure.multitenancy.TenantFilterBypass;
import com.fivucsas.identity.repository.UserRepository;
import com.fivucsas.identity.security.JwtService;
import com.fivucsas.identity.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Infrastructure adapter for {@link MembershipSwitchPort} — the ONLY bridge
 * between Phase-5 in-session membership switching ({@code SwitchMembershipService})
 * and the JPA {@code users} table + the post-login token-mint path.
 *
 * <p>Lives in {@code infrastructure..} (an {@code entity.User}-allowed package
 * per {@code UserDomainBoundaryTest}). It maps {@link User} rows into the
 * entity-free {@link SwitchTargetView} projection and, on a successful switch,
 * REUSES the exact token-mint primitives that
 * {@code VerifyMfaStepService.completeMfa} uses after a normal login:
 * {@link JwtService} for the access token and {@link RefreshTokenService} for a
 * normal refresh token — so the switched session is indistinguishable from a
 * fresh login of the target membership and subsequent {@code /auth/refresh}
 * works as that membership.</p>
 *
 * <p>Reads run with the Hibernate tenant filter bypassed ({@link
 * TenantFilterBypass}): a person's memberships span tenants by design (Model A),
 * and the application service has ALREADY enforced the same-identity HARD GATE
 * before any token is minted, so resolving the target row here is not a
 * cross-tenant leak.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MembershipSwitchAdapter implements MembershipSwitchPort {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TenantFilterBypass tenantFilterBypass;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
    @Transactional(readOnly = true)
    public Optional<SwitchTargetView> findSwitchTarget(UUID targetUserId) {
        if (targetUserId == null) {
            return Optional.empty();
        }
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findById(targetUserId))
                .map(this::toView);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean verifyPassword(UUID userId, String rawPassword) {
        if (userId == null || rawPassword == null || rawPassword.isEmpty()) {
            return false;
        }
        return tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findById(userId)
                        .map(User::getPasswordHash)
                        .filter(hash -> hash != null && !hash.isBlank())
                        .map(hash -> passwordEncoder.matches(rawPassword, hash))
                        .orElse(false));
    }

    @Override
    @Transactional
    public AuthResponse mintSwitchedTokens(UUID targetUserId,
                                           List<String> amr,
                                           Long authTime,
                                           UUID actorUserId,
                                           String ipAddress,
                                           String userAgent) {
        // Resolve the target as the one person's own row (filter bypassed). The
        // HARD GATE + switchability were already enforced by the service; we
        // re-load here transactionally to mint against a managed entity.
        User target = tenantFilterBypass.runWithoutTenantFilter(
                () -> userRepository.findById(targetUserId))
                .orElseThrow(() -> new IllegalStateException(
                        "Switch target disappeared before token mint: " + targetUserId));

        // --- access token: REUSE JwtService, subject = target email ----------
        // Carry over the caller's amr + auth_time (the person already
        // authenticated for THIS identity — no re-MFA for their own account) and
        // stamp act / switched_from = caller user id for traceability (RFC 8693
        // §4.1 actor claim shape).
        Map<String, Object> claims = new HashMap<>();
        if (amr != null && !amr.isEmpty()) {
            claims.put("amr", amr);
        }
        if (authTime != null) {
            claims.put("auth_time", authTime);
        }
        if (actorUserId != null) {
            // RFC 8693 token-exchange actor claim — { "act": { "sub": <caller> } }.
            Map<String, Object> act = new HashMap<>();
            act.put("sub", actorUserId.toString());
            claims.put("act", act);
            // Flat alias for log/audit tooling that greps a single claim.
            claims.put("switched_from", actorUserId.toString());
        }
        String accessToken = jwtService.generateToken(claims, target.getEmail());

        // --- refresh token: a NORMAL refresh token for the target membership --
        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(target, ipAddress, userAgent);

        UserResponse userResponse = UserResponseMapper.toResponse(target);

        return AuthResponse.of(
                accessToken,
                refreshToken.getToken(),
                jwtService.getExpirationMillis(),
                userResponse);
    }

    private SwitchTargetView toView(User u) {
        UUID tenantId = null;
        boolean tenantActive = false;
        try {
            Tenant tenant = u.getTenant();
            if (tenant != null) {
                tenantId = tenant.getId();
                tenantActive = tenant.isActive();
            }
        } catch (RuntimeException ex) {
            // Soft-deleted / missing tenant proxy — treat as not-switchable
            // (tenantActive stays false) rather than aborting.
            log.debug("Could not initialize tenant for user {}: {}", u.getId(), ex.toString());
        }

        // userActive = ACTIVE status AND not currently locked AND not soft-deleted.
        // The @SQLRestriction already filters soft-deleted rows out of findById,
        // but we re-check defensively. "Currently locked" honours lockedUntil:
        // an expired lock window is not a switch blocker.
        boolean currentlyLocked = u.isLocked()
                && (u.getLockedUntil() == null || Instant.now().isBefore(u.getLockedUntil()));
        boolean userActive = u.isActive() && !u.isSoftDeleted() && !currentlyLocked;

        return new SwitchTargetView(
                u.getId(),
                u.getIdentityId(),
                u.getEmail(),
                tenantId,
                userActive,
                tenantActive);
    }
}
