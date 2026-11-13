package com.fivucsas.identity.application.port.output;

import java.util.Optional;
import java.util.UUID;

/**
 * Resolves the tenant a user belongs to, from the user row's own {@code tenant_id}.
 *
 * <p>The answer never depends on the tenant the current request is bound to (a ROOT
 * switched with {@code X-Tenant-ID}, or the Hibernate {@code tenantFilter}): rows that
 * belong to a user, such as enrollments, are tagged with this tenant (PF-5).</p>
 */
public interface UserTenantPort {

    /** The user's own tenant id; empty when the user is unknown or has no tenant. */
    Optional<UUID> findTenantIdOfUser(UUID userId);
}
