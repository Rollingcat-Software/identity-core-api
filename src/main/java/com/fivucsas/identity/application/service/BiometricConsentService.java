package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.command.BiometricConsentRequest;
import com.fivucsas.identity.application.dto.response.BiometricConsentResponse;
import com.fivucsas.identity.application.port.input.ManageBiometricConsentUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.BiometricConsentResolver;
import com.fivucsas.identity.domain.exception.UnauthorizedException;
import com.fivucsas.identity.entity.IdentityTenantBiometricConsent;
import com.fivucsas.identity.repository.IdentityTenantBiometricConsentRepository;
import com.fivucsas.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages per-tenant biometric consent (Model A, Phase 3) AND resolves the
 * consent-gated canonical verify target.
 *
 * <p><b>Model A orchestration (LOW-RISK).</b> The biometric-processor's pgvector
 * store is NOT re-keyed. "One template per person" is achieved here: the api
 * designates a CANONICAL enrollment per (identity, method) and, when a tenant has
 * been granted consent, routes that tenant's verify to the canonical
 * {@code user_id}. A tenant never receives the raw template/embedding — only a
 * verify decision. Default-DENY: with no granted consent row the resolver returns
 * empty and the verify path behaves exactly as "not enrolled", leaking nothing.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BiometricConsentService
        implements ManageBiometricConsentUseCase, BiometricConsentResolver {

    private final IdentityTenantBiometricConsentRepository consentRepository;
    private final UserRepository userRepository;
    private final AuditLogPort auditLogPort;

    // ── ManageBiometricConsentUseCase ──────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public List<BiometricConsentResponse> listConsents(UUID identityId) {
        return consentRepository.findByIdentityId(identityId).stream()
                .map(BiometricConsentResponse::from)
                .toList();
    }

    @Override
    @Transactional
    public BiometricConsentResponse setConsent(UUID identityId, UUID actorUserId,
                                               BiometricConsentRequest request) {
        UUID tenantId = request.tenantId();
        // Normalize empty/blank method to null (= all methods).
        String method = (request.method() == null || request.method().isBlank())
                ? null : request.method().trim().toUpperCase();
        boolean grant = Boolean.TRUE.equals(request.granted());

        // Guard: the caller may only manage consent for a tenant where THEIR
        // identity has a membership. Identity ownership is proven upstream (the
        // identityId comes from the authenticated caller).
        if (!userRepository.identityHasMembershipInTenant(identityId, tenantId)) {
            log.warn("Consent change denied — identity {} has no membership in tenant {}",
                    identityId, tenantId);
            throw new UnauthorizedException(
                    "You may only manage biometric consent for tenants where you have a membership");
        }

        IdentityTenantBiometricConsent consent = consentRepository
                .findByIdentityIdAndTenantIdAndMethod(identityId, tenantId, method)
                .orElseGet(() -> IdentityTenantBiometricConsent.builder()
                        .identityId(identityId)
                        .tenantId(tenantId)
                        .method(method)
                        .build());
        consent.apply(grant);
        IdentityTenantBiometricConsent saved = consentRepository.save(consent);

        auditLogPort.logSecurityEvent(
                actorUserId != null ? actorUserId.toString() : null,
                "BIOMETRIC_CONSENT_CHANGED",
                null,
                String.format("identity=%s tenant=%s method=%s granted=%s",
                        identityId, tenantId, method == null ? "ALL" : method, grant));

        log.info("Biometric consent {} for identity {} tenant {} method {}",
                grant ? "granted" : "revoked", identityId, tenantId, method == null ? "ALL" : method);
        return BiometricConsentResponse.from(saved);
    }

    // ── BiometricConsentResolver ───────────────────────────────────────────

    @Override
    @Transactional(readOnly = true)
    public Optional<CanonicalTarget> resolveConsentedCanonicalTarget(UUID requestingUserId,
                                                                     String method) {
        String normMethod = method == null ? null : method.trim().toUpperCase();

        // 0) The requesting tenant = the user's own membership tenant.
        Optional<UUID> requestingTenantOpt = userRepository.findTenantIdById(requestingUserId);
        if (requestingTenantOpt.isEmpty() || requestingTenantOpt.get() == null) {
            return Optional.empty();
        }
        UUID requestingTenantId = requestingTenantOpt.get();

        // 1) Which identity (person) is this?
        Optional<UUID> identityIdOpt = userRepository.findIdentityIdById(requestingUserId);
        if (identityIdOpt.isEmpty() || identityIdOpt.get() == null) {
            return Optional.empty();
        }
        UUID identityId = identityIdOpt.get();

        // 2) Is there a canonical ENROLLED enrollment under a DIFFERENT tenant?
        List<Object[]> rows = userRepository.findCanonicalEnrollment(
                identityId, normMethod, requestingTenantId);
        if (rows.isEmpty()) {
            return Optional.empty();
        }

        // 3) Consent gate — default DENY. Either a method-specific or all-methods
        //    (method IS NULL) granted row authorizes the route.
        boolean consented = consentRepository
                .findApplicable(identityId, requestingTenantId, normMethod).stream()
                .anyMatch(IdentityTenantBiometricConsent::isGranted);
        if (!consented) {
            // No signal — caller MUST treat this identically to "not enrolled".
            return Optional.empty();
        }

        Object[] canonical = rows.get(0);
        UUID canonicalUserId = (UUID) canonical[0];
        UUID canonicalTenantId = (UUID) canonical[1];
        log.info("Consented cross-tenant verify: routing identity {} (tenant {} probe) to canonical user {} (tenant {}) for method {}",
                identityId, requestingTenantId, canonicalUserId, canonicalTenantId, normMethod);
        return Optional.of(new CanonicalTarget(canonicalUserId, canonicalTenantId));
    }
}
