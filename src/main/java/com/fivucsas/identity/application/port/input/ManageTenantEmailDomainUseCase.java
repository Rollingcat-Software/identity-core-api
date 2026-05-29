package com.fivucsas.identity.application.port.input;

import com.fivucsas.identity.application.dto.response.DomainVerificationChallengeResponse;
import com.fivucsas.identity.application.dto.response.DomainVerificationResultResponse;
import com.fivucsas.identity.application.dto.response.TenantEmailDomainResponse;

import java.util.List;
import java.util.UUID;

/**
 * Input port for managing a tenant's email-domain registry
 * ({@code tenant_email_domains}, V44).
 *
 * <p>Backs the admin CRUD API under
 * {@code /api/v1/tenants/{tenantId}/email-domains}. Hexagonal Architecture —
 * defines what the application can do; the REST controller is the driving
 * adapter and {@code ManageTenantEmailDomainService} the implementation.</p>
 */
public interface ManageTenantEmailDomainUseCase {

    /**
     * Lists every email domain owned by the tenant, primary first then
     * alphabetical.
     */
    List<TenantEmailDomainResponse> listDomains(UUID tenantId);

    /**
     * Adds an email domain to the tenant.
     *
     * @param domain    the FQDN to add (will be lowercased/trimmed); no '@'
     * @param isPrimary when {@code true}, this becomes the tenant's single
     *                  primary domain (any previous primary is dethroned)
     * @throws com.fivucsas.identity.domain.exception.TenantEmailDomainConflictException
     *         if the domain is already claimed by another tenant
     * @throws IllegalArgumentException if the domain fails format validation
     */
    TenantEmailDomainResponse addDomain(UUID tenantId, String domain, boolean isPrimary);

    /**
     * Removes an email domain from the tenant.
     *
     * @throws com.fivucsas.identity.domain.exception.TenantEmailDomainConflictException
     *         if this is the tenant's last domain and
     *         {@code enforce_domain_matching=true} (would lock out all signups)
     */
    void removeDomain(UUID tenantId, String domain);

    /**
     * Sets the given domain as the tenant's single primary domain, dethroning
     * any previous primary in the same transaction.
     */
    TenantEmailDomainResponse setPrimaryDomain(UUID tenantId, String domain);

    /**
     * Generates (or returns the existing) DNS-TXT verification challenge for a
     * tenant's email domain. Idempotent — repeated calls return the same token
     * until the domain is verified.
     *
     * @return the TXT record the admin must publish to prove ownership
     * @throws com.fivucsas.identity.exception.ResourceNotFoundException
     *         if the domain is not in this tenant's registry
     */
    DomainVerificationChallengeResponse requestDomainVerification(UUID tenantId, String domain);

    /**
     * Performs a DNS TXT lookup for the tenant's email domain and, if the
     * expected {@code fivucsas-domain-verification=<token>} record is present,
     * flips {@code verified=true} and clears the spent token.
     *
     * @param actingUserId the authenticated admin's user id for audit
     *                     attribution (never the tenant id — that would violate
     *                     audit_logs_user_id_fkey); may be {@code null}
     * @return a result with {@code verified=true} on success, or
     *         {@code verified=false} plus a reason on failure
     * @throws com.fivucsas.identity.exception.ResourceNotFoundException
     *         if the domain is not in this tenant's registry
     */
    DomainVerificationResultResponse verifyDomain(UUID tenantId, String domain, UUID actingUserId);
}
