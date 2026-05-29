package com.fivucsas.identity.application.port.input;

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
}
