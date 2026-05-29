package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.port.input.SwitchMembershipUseCase;
import com.fivucsas.identity.dto.AuthResponse;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.security.JwtService;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Phase-5 in-session membership switch endpoint (see
 * {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md} § "Phase 5").
 *
 * <p>{@code POST /api/v1/auth/switch-membership} — an authenticated person
 * assumes another of THEIR OWN linked memberships without re-login. Authenticated
 * by the default {@code /api/v1/**} rule in {@code SecurityConfig}.</p>
 *
 * <p>The caller's user id comes from the authenticated principal
 * ({@link RbacAuthorizationService#getCurrentUserId()} — the UUID helper, NOT
 * {@code getCurrentUser().getId()}, which would import {@code entity.User} and
 * trip {@code UserDomainBoundaryTest}). The caller's {@code amr} + {@code
 * auth_time} are read off the CURRENT bearer token (the person already
 * authenticated for this identity — no re-MFA for their own account) and carried
 * over by the service onto the newly-minted token. Nothing about WHO the caller
 * becomes is taken from the request beyond {@code targetUserId}.</p>
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication endpoints")
public class MembershipSwitchController {

    private final SwitchMembershipUseCase switchMembership;
    private final RbacAuthorizationService rbac;
    private final JwtService jwtService;

    @PostMapping("/switch-membership")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Assume another of your own linked memberships (token exchange)")
    public ResponseEntity<AuthResponse> switchMembership(
            @Valid @RequestBody SwitchMembershipRequest request,
            HttpServletRequest httpRequest) {

        UUID callerUserId = rbac.getCurrentUserId()
                .orElseThrow(() -> new InvalidCredentialsException("Authentication required"));

        // Carry over amr + auth_time from the CURRENT access token. We parse the
        // already-validated bearer token (the request reached here only because
        // JwtAuthenticationFilter authenticated it). A missing/unparseable claim
        // simply carries nothing — never a hard failure.
        List<String> amr = null;
        Long authTime = null;
        Claims claims = parseCurrentTokenClaims(httpRequest);
        if (claims != null) {
            amr = readAmr(claims);
            authTime = readAuthTime(claims);
        }

        AuthResponse response = switchMembership.switchMembership(
                callerUserId,
                request.getTargetUserId(),
                request.getPassword(),
                amr,
                authTime,
                getClientIp(httpRequest),
                getUserAgent(httpRequest));

        return ResponseEntity.ok(response);
    }

    private Claims parseCurrentTokenClaims(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        try {
            return jwtService.parseAllClaims(header.substring(7));
        } catch (RuntimeException e) {
            log.debug("Could not parse current token claims for switch carry-over: {}", e.toString());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> readAmr(Claims claims) {
        Object amr = claims.get("amr");
        if (amr instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return null;
    }

    private static Long readAuthTime(Claims claims) {
        Object at = claims.get("auth_time");
        if (at instanceof Number n) {
            return n.longValue();
        }
        // Fall back to the token's issued-at so the switched token still carries
        // a meaningful auth_time even when the source token predates the claim.
        try {
            if (claims.getIssuedAt() != null) {
                return claims.getIssuedAt().toInstant().getEpochSecond();
            }
        } catch (RuntimeException ignored) {
            // no iat — carry nothing
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf == null || xf.isEmpty() || "unknown".equalsIgnoreCase(xf)) {
            return request.getRemoteAddr();
        }
        return xf.split(",")[0].trim();
    }

    private String getUserAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return ua != null ? ua : "Unknown";
    }

    /** Request body for {@code POST /auth/switch-membership}. */
    @Data
    public static class SwitchMembershipRequest {

        /** The membership (users.id) the caller wants to assume. */
        @NotNull
        private UUID targetUserId;

        /**
         * Caller's current password — REQUIRED only when
         * {@code app.identity.require-stepup-on-switch=true}; otherwise ignored.
         */
        private String password;
    }
}
