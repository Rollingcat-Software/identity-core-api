package com.fivucsas.identity.repository;

import com.fivucsas.identity.entity.IdentityTenantBiometricConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data repository for the {@link IdentityTenantBiometricConsent} ledger
 * (Model A, Phase 3). Cross-tenant / platform-level — there is intentionally no
 * tenant-scoped variant (see the entity Javadoc).
 */
@Repository
public interface IdentityTenantBiometricConsentRepository
        extends JpaRepository<IdentityTenantBiometricConsent, UUID> {

    /** All consent rows for one identity (the "my consents" view). */
    List<IdentityTenantBiometricConsent> findByIdentityId(UUID identityId);

    /**
     * The exact (identity, tenant, method) row — used by grant/revoke to upsert.
     * {@code method} may be {@code null} (the all-methods singleton); Spring Data
     * derives {@code method IS NULL} for a null argument.
     */
    Optional<IdentityTenantBiometricConsent> findByIdentityIdAndTenantIdAndMethod(
            UUID identityId, UUID tenantId, String method);

    /**
     * Rows that could authorize a verify of {@code method} for (identity, tenant):
     * either the method-specific row OR the all-methods (method IS NULL) row. The
     * consent-resolution logic treats the table as default-DENY, so a missing or
     * non-granted row yields no signal.
     */
    @Query("SELECT c FROM IdentityTenantBiometricConsent c "
            + "WHERE c.identityId = :identityId AND c.tenantId = :tenantId "
            + "AND (c.method = :method OR c.method IS NULL)")
    List<IdentityTenantBiometricConsent> findApplicable(
            @Param("identityId") UUID identityId,
            @Param("tenantId") UUID tenantId,
            @Param("method") String method);
}
