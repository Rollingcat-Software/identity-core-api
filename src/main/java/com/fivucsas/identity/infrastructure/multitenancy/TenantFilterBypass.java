package com.fivucsas.identity.infrastructure.multitenancy;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Session;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.function.Supplier;

/**
 * Runs a unit of repository work with the Hibernate {@code tenantFilter}
 * temporarily disabled, restoring it afterwards.
 *
 * <p><b>Why this exists — the ROOT tenant-switcher 403.</b> When a
 * ROOT selects a foreign tenant (via {@code X-Tenant-ID}),
 * {@link TenantContext} carries that foreign tenant for the whole request, and
 * {@link TenantHibernateAspect} enables {@code tenantFilter = <foreign>} on
 * every {@code repository..} call. That correctly scopes the DATA the admin is
 * browsing — but it ALSO scoped the admin's OWN identity lookup
 * ({@code findByEmail}) used to authenticate and to resolve permissions. A
 * ROOT user's row lives in the system tenant ({@code 000…000}), so it was
 * filtered out under a foreign active tenant → {@code getCurrentUser()} /
 * {@code loadUserByUsername()} returned empty → {@code @PreAuthorize} resolved
 * NO authorities → Spring returned <b>403 "Access Denied"</b>. In other words,
 * switching tenants broke the switcher's own authorization.</p>
 *
 * <p><b>Why disabling the filter for the self-lookup is SAFE (not a leak).</b>
 * The caller's identity is resolved by their globally-unique, already-
 * authenticated email (or by their own id). It answers the question "who is
 * the caller and what may they do", which is intrinsically caller-scoped and
 * independent of which tenant's data they are currently browsing. A caller can
 * only ever resolve THEIR OWN row this way — they cannot enumerate other
 * tenants' users through it. The {@code @SQLRestriction("deleted_at IS NULL")}
 * soft-delete guard on {@code User} is NOT a Hibernate {@code @Filter} and is
 * therefore untouched here: soft-deleted users still cannot authenticate.</p>
 *
 * <p><b>Interaction with {@link TenantHibernateAspect}.</b> The aspect runs
 * {@code @Before} EVERY {@code repository..} call and re-enables
 * {@code tenantFilter} from {@link TenantContext} whenever the filter is not
 * already enabled. So merely disabling the filter is not enough — the very next
 * repository call inside {@code work} would re-enable it. We therefore also
 * clear {@link TenantContext} for the duration (the aspect only enables the
 * filter when a tenant is present), and restore both afterwards.</p>
 *
 * <p>Lives in {@code infrastructure.multitenancy} (an {@code entity.User}-
 * boundary-allowed package) so {@code security} callers can use it without
 * touching the JPA {@link Session} directly.</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TenantFilterBypass {

    private static final String TENANT_FILTER = "tenantFilter";

    private final EntityManager entityManager;

    /**
     * Executes {@code work} with {@code tenantFilter} disabled for the current
     * Hibernate {@link Session}, then restores the prior enablement/parameter
     * state. If no filter was enabled, nothing is re-enabled.
     *
     * <p>Must run inside a transaction (the callers are {@code @Transactional}).</p>
     */
    public <T> T runWithoutTenantFilter(Supplier<T> work) {
        Session session = entityManager.unwrap(Session.class);
        boolean wasEnabled = session.getEnabledFilter(TENANT_FILTER) != null;
        // The aspect sets the filter parameter from TenantContext, so that is the
        // authoritative value to restore (org.hibernate.Filter exposes no getter
        // for the current parameter value).
        UUID tenantId = TenantContext.getCurrentTenant();

        // (1) Drop any already-enabled filter on this Session, and (2) clear
        // TenantContext so TenantHibernateAspect does NOT re-enable the filter
        // on the repository call(s) inside work.get().
        if (wasEnabled) {
            session.disableFilter(TENANT_FILTER);
        }
        if (tenantId != null) {
            TenantContext.clear();
        }
        if (wasEnabled || tenantId != null) {
            log.trace("tenantFilter suppressed for caller self-resolution");
        }
        try {
            return work.get();
        } finally {
            // Restore TenantContext first so a subsequent aspect-driven re-enable
            // (or our explicit re-enable below) uses the right tenant id.
            if (tenantId != null) {
                TenantContext.setCurrentTenant(tenantId);
            }
            if (wasEnabled && tenantId != null) {
                // Re-enable with the same tenant id the aspect originally set so
                // the rest of the request keeps its data scope.
                session.enableFilter(TENANT_FILTER).setParameter("tenantId", tenantId);
                log.trace("tenantFilter restored after caller self-resolution");
            }
        }
    }
}
