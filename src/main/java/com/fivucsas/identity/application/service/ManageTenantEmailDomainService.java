package com.fivucsas.identity.application.service;

import com.fivucsas.identity.application.dto.response.DomainVerificationChallengeResponse;
import com.fivucsas.identity.application.dto.response.DomainVerificationResultResponse;
import com.fivucsas.identity.application.dto.response.TenantEmailDomainResponse;
import com.fivucsas.identity.application.port.input.ManageTenantEmailDomainUseCase;
import com.fivucsas.identity.application.port.output.AuditLogPort;
import com.fivucsas.identity.application.port.output.DnsTxtLookupPort;
import com.fivucsas.identity.domain.exception.TenantEmailDomainConflictException;
import com.fivucsas.identity.domain.exception.TenantNotFoundException;
import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantEmailDomain;
import com.fivucsas.identity.entity.TenantEmailDomainId;
import com.fivucsas.identity.repository.JpaTenantRepository;
import com.fivucsas.identity.repository.TenantEmailDomainRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Application service for the tenant email-domain registry CRUD
 * ({@code tenant_email_domains}, V44).
 *
 * <p>Implements {@link ManageTenantEmailDomainUseCase}. Tenant-scope / RBAC
 * gating happens at the controller via {@code @PreAuthorize}; this service
 * enforces the domain-level invariants (format, single-owner uniqueness,
 * single-primary, last-domain-while-enforced) and emits audit events.</p>
 *
 * <p>This class lives in the {@code application} package and uses
 * {@code entity.TenantEmailDomain}/{@code entity.Tenant} directly. That is
 * permitted: the {@code UserDomainBoundaryTest} ArchUnit ratchet freezes only
 * {@code entity.User}; the tenant-email-domain aggregate has a single JPA
 * model. {@code RegisterUserService} establishes the same precedent.</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ManageTenantEmailDomainService implements ManageTenantEmailDomainUseCase {

    /**
     * Basic FQDN validation: one-or-more dot-separated labels (a-z, 0-9, '-')
     * with a final alphabetic TLD of at least two chars. Lowercase only — the
     * caller normalises before this check. Deliberately permissive (we are not
     * resolving DNS), just enough to reject obvious garbage and '@'.
     */
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$");

    /**
     * DNS host PREFIX under which the verification TXT record must live, e.g.
     * {@code _fivucsas-verify.example.com}. A dedicated sub-name (rather than the
     * apex) keeps the verification record out of the way of SPF/DMARC/etc. apex
     * TXT records and is the industry pattern (Google, AWS ACM, etc.).
     */
    static final String VERIFY_HOST_PREFIX = "_fivucsas-verify.";

    /** Prefix of the TXT record VALUE: {@code fivucsas-domain-verification=<token>}. */
    static final String VERIFY_VALUE_PREFIX = "fivucsas-domain-verification=";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final TenantEmailDomainRepository emailDomainRepository;
    private final JpaTenantRepository tenantRepository;
    private final AuditLogPort auditLogPort;
    private final DnsTxtLookupPort dnsTxtLookupPort;

    @Override
    @Transactional(readOnly = true)
    public List<TenantEmailDomainResponse> listDomains(UUID tenantId) {
        requireTenant(tenantId);
        return emailDomainRepository.findByIdTenantId(tenantId).stream()
                .sorted(Comparator
                        .comparing((TenantEmailDomain d) -> !d.isPrimary())
                        .thenComparing(TenantEmailDomain::getEmailDomain))
                .map(ManageTenantEmailDomainService::toResponse)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public TenantEmailDomainResponse addDomain(UUID tenantId, String domain, boolean isPrimary) {
        requireTenant(tenantId);
        String normalized = normalizeAndValidate(domain);

        // Reject up-front if another tenant already owns this domain. The unique
        // index ux_tenant_email_domains_domain also enforces this, but the
        // pre-check lets us return a clean 409 instead of leaking a raw 500.
        emailDomainRepository.findByIdEmailDomainIgnoreCase(normalized).ifPresent(existing -> {
            if (!existing.getTenantId().equals(tenantId)) {
                throw TenantEmailDomainConflictException.alreadyClaimed(normalized);
            }
            // Same tenant already owns it — treat add as idempotent no-op below.
        });

        // Idempotent: if this tenant already owns the domain, just return it
        // (optionally promoting to primary if requested).
        var owned = emailDomainRepository.findById(TenantEmailDomainId.of(tenantId, normalized));
        if (owned.isPresent()) {
            if (isPrimary && !owned.get().isPrimary()) {
                return setPrimaryDomain(tenantId, normalized);
            }
            return toResponse(owned.get());
        }

        if (isPrimary) {
            dethroneCurrentPrimary(tenantId);
        }

        // Admin/ROOT CRUD adds are trusted (an authenticated tenant admin or
        // ROOT is asserting ownership), so they are verified=true and keep their
        // existing auto-bind + enforce_domain_matching behaviour. Only the
        // PUBLIC self-service onboarding claim is verified=false (V63).
        TenantEmailDomain row = TenantEmailDomain.create(tenantId, normalized, isPrimary, true);
        try {
            row = emailDomainRepository.saveAndFlush(row);
        } catch (DataIntegrityViolationException e) {
            // Race: another tenant claimed the domain between our pre-check and
            // the insert. The unique index caught it — surface a clean 409.
            log.warn("Domain '{}' claim raced and lost the unique index for tenant {}", normalized, tenantId);
            throw TenantEmailDomainConflictException.alreadyClaimed(normalized);
        }

        auditLogPort.logSecurityEvent(
                tenantId.toString(),
                "TENANT_EMAIL_DOMAIN_ADDED",
                null,
                String.format("Email domain '%s' added (primary=%s)", normalized, isPrimary));

        return toResponse(row);
    }

    @Override
    @Transactional
    public void removeDomain(UUID tenantId, String domain) {
        Tenant tenant = requireTenant(tenantId);
        String normalized = normalizeAndValidate(domain);

        TenantEmailDomain row = emailDomainRepository
                .findById(TenantEmailDomainId.of(tenantId, normalized))
                .orElseThrow(() -> new com.fivucsas.identity.exception.ResourceNotFoundException(
                        "Email domain not found for this tenant: " + normalized));

        // Refuse to remove the LAST domain when enforcement is on — that would
        // make every future signup fail EmailDomainNotAllowedException, locking
        // the tenant out of new registrations entirely.
        long remaining = emailDomainRepository.findByIdTenantId(tenantId).size();
        if (tenant.isEnforceDomainMatching() && remaining <= 1) {
            throw TenantEmailDomainConflictException.lastDomain(normalized);
        }

        emailDomainRepository.delete(row);

        auditLogPort.logSecurityEvent(
                tenantId.toString(),
                "TENANT_EMAIL_DOMAIN_REMOVED",
                null,
                String.format("Email domain '%s' removed", normalized));
    }

    @Override
    @Transactional
    public TenantEmailDomainResponse setPrimaryDomain(UUID tenantId, String domain) {
        requireTenant(tenantId);
        String normalized = normalizeAndValidate(domain);

        TenantEmailDomain target = emailDomainRepository
                .findById(TenantEmailDomainId.of(tenantId, normalized))
                .orElseThrow(() -> new com.fivucsas.identity.exception.ResourceNotFoundException(
                        "Email domain not found for this tenant: " + normalized));

        if (target.isPrimary()) {
            return toResponse(target); // already primary — no-op
        }

        // Dethrone-then-promote, flushing between, to respect the partial unique
        // index ux_tenant_email_domains_one_primary(tenant_id) WHERE is_primary.
        // Mirrors the uq_auth_flow_default dethrone in ManageAuthFlowService:
        // the index is checked per-statement, so the old primary's slot must be
        // freed (and flushed) before the new primary claims it, else 23505.
        dethroneCurrentPrimary(tenantId);
        target.markPrimary();
        TenantEmailDomain saved = emailDomainRepository.saveAndFlush(target);

        auditLogPort.logSecurityEvent(
                tenantId.toString(),
                "TENANT_EMAIL_DOMAIN_PRIMARY_SET",
                null,
                String.format("Email domain '%s' set as primary", normalized));

        return toResponse(saved);
    }

    @Override
    @Transactional
    public DomainVerificationChallengeResponse requestDomainVerification(UUID tenantId, String domain) {
        requireTenant(tenantId);
        String normalized = normalizeAndValidate(domain);

        TenantEmailDomain row = emailDomainRepository
                .findById(TenantEmailDomainId.of(tenantId, normalized))
                .orElseThrow(() -> new com.fivucsas.identity.exception.ResourceNotFoundException(
                        "Email domain not found for this tenant: " + normalized));

        // Already verified — return a no-op challenge so the UI can show the
        // verified state without issuing a pointless token.
        if (row.isVerified()) {
            return buildChallenge(row, normalized);
        }

        // Idempotent: reuse the existing token if one was already issued so the
        // admin who published the record can still verify after a page reload.
        if (row.getVerificationToken() == null || row.getVerificationToken().isBlank()) {
            row.issueVerificationToken(generateToken());
            row = emailDomainRepository.saveAndFlush(row);
            log.info("Issued DNS-TXT verification token for tenant {} domain '{}'", tenantId, normalized);
        }

        return buildChallenge(row, normalized);
    }

    @Override
    @Transactional
    public DomainVerificationResultResponse verifyDomain(UUID tenantId, String domain, UUID actingUserId) {
        requireTenant(tenantId);
        String normalized = normalizeAndValidate(domain);

        TenantEmailDomain row = emailDomainRepository
                .findById(TenantEmailDomainId.of(tenantId, normalized))
                .orElseThrow(() -> new com.fivucsas.identity.exception.ResourceNotFoundException(
                        "Email domain not found for this tenant: " + normalized));

        if (row.isVerified()) {
            // Idempotent success — already proven.
            return DomainVerificationResultResponse.builder()
                    .domain(normalized)
                    .verified(true)
                    .reason("ALREADY_VERIFIED")
                    .message("Domain is already verified.")
                    .build();
        }

        String token = row.getVerificationToken();
        if (token == null || token.isBlank()) {
            return DomainVerificationResultResponse.builder()
                    .domain(normalized)
                    .verified(false)
                    .reason("NO_CHALLENGE")
                    .message("No verification challenge has been requested for this domain. "
                            + "Request one first, publish the TXT record, then verify.")
                    .build();
        }

        String host = VERIFY_HOST_PREFIX + normalized;
        String expectedValue = VERIFY_VALUE_PREFIX + token;
        List<String> records = dnsTxtLookupPort.lookupTxtRecords(host);
        boolean match = records != null && records.stream()
                .filter(java.util.Objects::nonNull)
                .map(String::trim)
                .anyMatch(expectedValue::equals);

        if (!match) {
            // Audit the failed attempt under the ACTING ADMIN's user id (or null
            // for system) — NEVER the tenant id, which is not an FK into users
            // and would violate audit_logs_user_id_fkey.
            auditLogPort.logSecurityEvent(
                    actingUserId != null ? actingUserId.toString() : null,
                    "TENANT_EMAIL_DOMAIN_VERIFY_FAILED",
                    null,
                    String.format("DNS-TXT verification failed for domain '%s' (tenant=%s): "
                            + "expected record not found at %s", normalized, tenantId, host));
            return DomainVerificationResultResponse.builder()
                    .domain(normalized)
                    .verified(false)
                    .reason("RECORD_NOT_FOUND")
                    .message("Expected TXT record not found at " + host + ". "
                            + "DNS changes can take a few minutes to propagate — try again shortly.")
                    .build();
        }

        row.markVerifiedViaDns();
        emailDomainRepository.saveAndFlush(row);

        auditLogPort.logSecurityEvent(
                actingUserId != null ? actingUserId.toString() : null,
                "TENANT_EMAIL_DOMAIN_VERIFIED",
                null,
                String.format("DNS-TXT ownership verified for domain '%s' (tenant=%s)",
                        normalized, tenantId));
        log.info("DNS-TXT ownership verified for tenant {} domain '{}'", tenantId, normalized);

        return DomainVerificationResultResponse.builder()
                .domain(normalized)
                .verified(true)
                .build();
    }

    // ========== Helpers ==========

    /**
     * Clears the current primary domain (if any) for the tenant and flushes,
     * freeing the partial-unique-index slot before a new primary claims it.
     */
    private void dethroneCurrentPrimary(UUID tenantId) {
        emailDomainRepository.findByIdTenantId(tenantId).stream()
                .filter(TenantEmailDomain::isPrimary)
                .forEach(d -> {
                    d.clearPrimary();
                    emailDomainRepository.saveAndFlush(d);
                });
    }

    /**
     * Generates a URL-safe, unpadded 256-bit random token suitable for a DNS
     * TXT value (no '=' padding, which keeps the record clean).
     */
    private static String generateToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static DomainVerificationChallengeResponse buildChallenge(TenantEmailDomain row, String normalized) {
        String host = VERIFY_HOST_PREFIX + normalized;
        String value = row.getVerificationToken() != null
                ? VERIFY_VALUE_PREFIX + row.getVerificationToken()
                : null;
        String instructions = row.isVerified()
                ? "Domain '" + normalized + "' is already verified."
                : "Add a DNS TXT record with host '" + host + "' and value '" + value
                  + "', then call the verify endpoint. DNS changes may take a few minutes to propagate.";
        return DomainVerificationChallengeResponse.builder()
                .domain(normalized)
                .verified(row.isVerified())
                .recordName(host)
                .recordType("TXT")
                .recordValue(value)
                .requestedAt(row.getVerificationRequestedAt())
                .instructions(instructions)
                .build();
    }

    private Tenant requireTenant(UUID tenantId) {
        return tenantRepository.findById(tenantId)
                .orElseThrow(() -> new TenantNotFoundException(tenantId.toString()));
    }

    /**
     * Lowercases + trims, rejects '@', and validates basic FQDN shape.
     * Throws {@link IllegalArgumentException} (→ 400 via GlobalExceptionHandler)
     * on malformed input.
     */
    private String normalizeAndValidate(String domain) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("Email domain must not be blank");
        }
        String normalized = domain.toLowerCase().trim();
        if (normalized.indexOf('@') >= 0) {
            throw new IllegalArgumentException(
                    "Email domain must not contain '@' (supply the domain only, e.g. 'marmara.edu.tr')");
        }
        if (!DOMAIN_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Invalid email domain format: " + normalized);
        }
        return normalized;
    }

    private static TenantEmailDomainResponse toResponse(TenantEmailDomain d) {
        return TenantEmailDomainResponse.builder()
                .domain(d.getEmailDomain())
                .isPrimary(d.isPrimary())
                .createdAt(d.getCreatedAt())
                .build();
    }
}
