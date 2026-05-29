package com.fivucsas.identity.controller;

import com.fivucsas.identity.application.dto.command.BiometricConsentRequest;
import com.fivucsas.identity.application.dto.response.BiometricConsentResponse;
import com.fivucsas.identity.application.port.input.ManageBiometricConsentUseCase;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.security.RbacAuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Per-tenant biometric CONSENT endpoints for the caller's own identity (Model A,
 * Phase 3). A person enrols their biometric once; joining a new tenant becomes a
 * consent toggle rather than a re-capture. The tenant never receives the raw
 * template — only a verify decision, and only when consent is granted.
 *
 * <p>The actor + identity are derived from the authenticated principal via
 * {@link RbacAuthorizationService} ({@code getCurrentUserId()} /
 * {@code getCurrentUserIdentityId()}) — NOT {@code getCurrentUser().getId()},
 * which would trip {@code UserDomainBoundaryTest}.</p>
 */
@RestController
@RequestMapping("/api/v1/identity/biometric/consents")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Biometric Consent",
        description = "Per-tenant consent to verify against the caller's canonical biometric template (Model A)")
public class BiometricConsentController {

    private final ManageBiometricConsentUseCase manageBiometricConsentUseCase;
    private final RbacAuthorizationService rbacService;

    @GetMapping
    @Operation(summary = "List the caller's per-tenant biometric consents")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<BiometricConsentResponse>> listConsents() {
        UUID identityId = rbacService.getCurrentUserIdentityId()
                .orElseThrow(UnauthorizedException::new);
        return ResponseEntity.ok(manageBiometricConsentUseCase.listConsents(identityId));
    }

    @PostMapping
    @Operation(summary = "Grant or revoke biometric consent for a tenant the caller belongs to")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<BiometricConsentResponse> setConsent(
            @Valid @RequestBody BiometricConsentRequest request) {
        UUID identityId = rbacService.getCurrentUserIdentityId()
                .orElseThrow(UnauthorizedException::new);
        UUID actorUserId = rbacService.getCurrentUserId().orElse(null);
        return ResponseEntity.ok(
                manageBiometricConsentUseCase.setConsent(identityId, actorUserId, request));
    }
}
