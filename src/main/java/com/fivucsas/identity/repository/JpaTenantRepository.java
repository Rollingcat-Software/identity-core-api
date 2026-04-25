package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.Tenant;
import com.fivucsas.identity.entity.TenantStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA Repository for Tenant entity.
 * Pure infrastructure concern - no domain interfaces.
 * The TenantRepositoryAdapter bridges this to the domain layer.
 */
@Repository
public interface JpaTenantRepository extends JpaRepository<Tenant, UUID> {

    Optional<Tenant> findBySlug(String slug);

    Optional<Tenant> findByName(String name);

    List<Tenant> findByStatus(TenantStatus status);

    boolean existsBySlug(String slug);

    boolean existsByName(String name);

    long countByStatus(TenantStatus status);

    /**
     * Legacy single-domain lookup against the {@code tenants.domain} column,
     * which is not mapped on the {@link Tenant} JPA entity (the column
     * pre-dates the entity and is being deprecated by V44's
     * {@code tenant_email_domains} table).
     *
     * <p>Used as a fall-back during the V44 rollout so tenants whose admin
     * has not yet migrated to {@code tenant_email_domains} continue to
     * resolve correctly on registration. The match is case-insensitive and
     * scoped to non-soft-deleted rows.</p>
     *
     * @param emailDomain the domain part of the user's email
     * @return the matching tenant if one claims this domain via the legacy
     *         column; otherwise empty
     */
    @Query(value = "SELECT * FROM tenants " +
        "WHERE deleted_at IS NULL " +
        "  AND domain IS NOT NULL " +
        "  AND lower(domain) = lower(:emailDomain) " +
        "LIMIT 1",
        nativeQuery = true)
    Optional<Tenant> findByLegacyDomainIgnoreCase(@Param("emailDomain") String emailDomain);
}
