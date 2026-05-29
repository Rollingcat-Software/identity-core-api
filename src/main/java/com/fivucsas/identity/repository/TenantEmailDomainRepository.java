package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.TenantEmailDomain;
import com.fivucsas.identity.entity.TenantEmailDomainId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for {@link TenantEmailDomain}.
 *
 * <p>Backs the email-domain → tenant lookup used during registration so a
 * new user is auto-assigned to the tenant that owns their email domain.
 * The {@code email_domain} column is unique across all tenants (V44), so a
 * domain lookup yields at most one tenant.</p>
 *
 * <p>The composite ID field names ({@code idEmailDomain}, {@code idTenantId})
 * follow Spring Data JPA's derived-query convention for {@link jakarta.persistence.EmbeddedId}
 * properties — Spring traverses {@code TenantEmailDomain.id.emailDomain} and
 * {@code TenantEmailDomain.id.tenantId} respectively.</p>
 */
@Repository
public interface TenantEmailDomainRepository
    extends JpaRepository<TenantEmailDomain, TenantEmailDomainId> {

    /**
     * Look up the tenant-email-domain row for a given email domain
     * (case-insensitive). Used on registration to resolve the user's tenant
     * from the domain part of their email address.
     *
     * @param emailDomain the domain part of an email address (e.g.
     *                    {@code "marmara.edu.tr"} or {@code "MARUN.edu.tr"})
     * @return the matching row, or {@link Optional#empty()} if no tenant
     *         claims this domain
     */
    Optional<TenantEmailDomain> findByIdEmailDomainIgnoreCase(String emailDomain);

    /**
     * Look up a VERIFIED tenant-email-domain row for a given email domain
     * (case-insensitive). Used on registration so that only domains whose
     * ownership has been proven (DNS-TXT verification — Round 2 — or admin
     * provisioning) auto-bind new registrants or satisfy
     * {@code enforce_domain_matching}. A self-service-claimed but still
     * unverified domain (V63) must NOT pull in other users.
     *
     * @param emailDomain the domain part of an email address
     * @return the matching VERIFIED row, or {@link Optional#empty()}
     */
    Optional<TenantEmailDomain> findByIdEmailDomainIgnoreCaseAndVerifiedTrue(String emailDomain);

    /**
     * List every email domain owned by a given tenant. Used by the tenant
     * admin UI to display and manage the list of claimed domains.
     *
     * @param tenantId the tenant identifier
     * @return all rows belonging to the tenant; empty list if none
     */
    List<TenantEmailDomain> findByIdTenantId(UUID tenantId);
}
