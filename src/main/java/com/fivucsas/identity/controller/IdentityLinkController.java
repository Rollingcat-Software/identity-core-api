package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.response.IdentityMeResponse;
import com.fivucsas.identity.application.port.input.IdentityLinkUseCase;
import com.fivucsas.identity.domain.exception.InvalidCredentialsException;
import com.fivucsas.identity.security.RbacAuthorizationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Phase-2 account-linking endpoints (see
 * {@code docs/IDENTITY_ACCOUNT_LINKING_DESIGN.md} § "Phase 2").
 *
 * <p>Every endpoint is authenticated (default {@code /api/v1/**} rule in
 * {@code SecurityConfig}). The caller's identity is ALWAYS derived from the
 * authenticated principal via {@link RbacAuthorizationService#getCurrentUserId()}
 * (the UUID helper — NOT {@code getCurrentUser().getId()}, which would import
 * {@code entity.User} and trip {@code UserDomainBoundaryTest}). No endpoint takes
 * the caller's identity from a request parameter, so a caller can only ever
 * operate on their OWN identity.</p>
 */
@RestController
@RequestMapping("/api/v1/identity")
@RequiredArgsConstructor
@Slf4j
public class IdentityLinkController {

    private final IdentityLinkUseCase identityLink;
    private final RbacAuthorizationService rbac;

    /**
     * Begins a link: sends an OTP to the target email (proof of control).
     * Returns 202 Accepted — the code is in flight.
     */
    @PostMapping("/link/initiate")
    public ResponseEntity<Void> initiate(@Valid @RequestBody LinkInitiateRequest request) {
        UUID callerUserId = currentUserId();
        identityLink.initiateLink(callerUserId, request.getEmail());
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    /**
     * Completes a link: verifies the OTP AND the caller's step-up password,
     * then folds the target membership into the caller's identity.
     */
    @PostMapping("/link/confirm")
    public ResponseEntity<Void> confirm(@Valid @RequestBody LinkConfirmRequest request) {
        UUID callerUserId = currentUserId();
        identityLink.confirmLink(callerUserId, request.getEmail(), request.getOtp(),
                request.getPassword());
        return ResponseEntity.noContent().build();
    }

    /**
     * Reverses a link: splits the named membership back out into a fresh
     * identity. The caller may only unlink memberships within their own identity.
     */
    @PostMapping("/unlink")
    public ResponseEntity<Void> unlink(@Valid @RequestBody UnlinkRequest request) {
        UUID callerUserId = currentUserId();
        identityLink.unlink(callerUserId, request.getMembershipUserId());
        return ResponseEntity.noContent().build();
    }

    /**
     * The person view: the caller's identity, controlled emails and memberships
     * across all tenants.
     */
    @GetMapping("/me")
    public ResponseEntity<IdentityMeResponse> me() {
        UUID callerUserId = currentUserId();
        return ResponseEntity.ok(identityLink.getMyIdentity(callerUserId));
    }

    private UUID currentUserId() {
        return rbac.getCurrentUserId()
                .orElseThrow(() -> new InvalidCredentialsException("Authentication required"));
    }

    // ---- request DTOs ------------------------------------------------------

    @Data
    public static class LinkInitiateRequest {
        @NotBlank
        @Email
        private String email;
    }

    @Data
    public static class LinkConfirmRequest {
        @NotBlank
        @Email
        private String email;

        @NotBlank
        private String otp;

        /** Caller's current password for step-up re-authentication. */
        @NotBlank
        private String password;
    }

    @Data
    public static class UnlinkRequest {
        @NotNull
        private UUID membershipUserId;
    }
}
